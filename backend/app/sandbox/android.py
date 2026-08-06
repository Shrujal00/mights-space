"""Android detonation: run the app on a throwaway phone and watch what it does.

The caseload this exists for is Indian mobile fraud — apps posing as a bank, an
RTO e-Challan notice or a light-bill reminder, whose real purpose is to read the
victim's text messages and forward the one-time codes. Static analysis can show
such an app *asks* for SMS permission. Only running it shows the app reading 247
messages and posting them to an address three seconds later.

The sandbox is an emulator started with `-wipe-data` on every run, so each sample
gets a phone with no accounts, no contacts and no history, and no sample ever
sees what a previous one left behind.

Two rules hold throughout:

* Nothing here raises at its caller. Every failure comes back as a failed
  `DetonationResult` so a sandbox that will not start costs the report its
  dynamic section and nothing more.
* The emulator is always shut down, including on the paths that failed. A leaked
  emulator holds several gigabytes and blocks the next run, since detonations
  are deliberately serialised.
"""

import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from ..analysis.apk_analysis import analyze_apk
from ..analysis.behavior import (
    CATEGORIES,
    COMPLETE,
    TIMEOUT,
    BehaviorEvent,
    DetonationResult,
)

ANDROID = "android"
FRIDA = "frida"

HOOK_SCRIPT = Path(__file__).parent / "hooks" / "android.js"

# A hook message is untrusted: it is produced inside the sandbox, in the same
# process as the sample. Fields are bounded before they reach a report.
MAX_TARGET_CHARS = 512
MAX_DETAIL_CHARS = 256

DEFAULT_AVD = "triage"
DEFAULT_DWELL_SECONDS = 45
DEFAULT_BOOT_TIMEOUT_SECONDS = 300


# --------------------------------------------------------------------------
# Pure: hook messages to behaviour events
# --------------------------------------------------------------------------


def event_from_payload(payload, started_at: datetime) -> BehaviorEvent | None:
    """One hook message, validated into an event — or None if it is unusable.

    Rejection is deliberate rather than best-effort. The hooks share a process
    with the sample, so a message is input from inside the sandbox; a category
    the report does not know how to render must not reach the report, and a byte
    count that is not a number must not be guessed at, because both end up in a
    document presented as evidence.
    """
    if not isinstance(payload, dict):
        return None

    category = payload.get("category")
    if category not in CATEGORIES:
        return None

    action, target = payload.get("action"), payload.get("target")
    if not isinstance(action, str) or not isinstance(target, str) or not target:
        return None

    return BehaviorEvent.since(
        started_at,
        _moment(payload.get("ts"), started_at),
        category=category,
        action=action[:MAX_DETAIL_CHARS],
        target=target[:MAX_TARGET_CHARS],
        detail=str(payload.get("detail") or "")[:MAX_DETAIL_CHARS],
        source=FRIDA,
        size_bytes=_whole_number(payload.get("bytes")),
        record_count=_whole_number(payload.get("count")),
    )


# Two reports of the same action closer together than this are the framework
# delegating one call through several methods, not the app acting twice.
DUPLICATE_WINDOW_MS = 50


def events_from_payloads(payloads, started_at: datetime) -> list[BehaviorEvent]:
    """Every usable message, in order, with the framework's echoes removed."""
    events = [event_from_payload(payload, started_at) for payload in payloads]
    ordered = sorted(
        (event for event in events if event is not None), key=lambda e: e.offset_ms
    )
    return _collapse_echoes(ordered)


def _collapse_echoes(events: list[BehaviorEvent]) -> list[BehaviorEvent]:
    """Drop repeats that are one action seen more than once.

    `ContentResolver.query` has several overloads and Android implements the
    short ones by calling the long ones, so hooking them all means a single read
    by the app fires the hook two or three times. Counting those separately
    would multiply one observation into several and inflate the number of
    exfiltration findings drawn from it.

    Only exact repeats within a few tens of milliseconds are collapsed. An app
    that genuinely reads the inbox twice, seconds apart, still shows twice — and
    two reads returning different row counts are always distinct, because those
    are different facts.
    """
    kept: list[BehaviorEvent] = []
    for event in events:
        echo = any(
            previous.category == event.category
            and previous.action == event.action
            and previous.target == event.target
            and previous.detail == event.detail
            and event.offset_ms - previous.offset_ms <= DUPLICATE_WINDOW_MS
            for previous in reversed(kept[-4:])
        )
        if not echo:
            kept.append(event)
    return kept


def split_messages(messages) -> tuple[list, list[str]]:
    """Separate what the hooks reported from what went wrong in them.

    Frida delivers hook output and script faults down the same channel. Ignoring
    the faults is how a broken script turns into a clean, empty report — so they
    are pulled out and kept.
    """
    payloads, errors = [], []
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("type") == "send":
            payloads.append(message.get("payload"))
        elif message.get("type") == "error":
            description = message.get("description") or "the hook script failed"
            line = message.get("lineNumber")
            errors.append(f"{description} (line {line})" if line else description)
    return payloads, errors


def result_from_observation(
    *,
    started_at: datetime,
    payloads: list,
    errors: list[str],
    artifacts: dict[str, str],
    conditions: str,
    status: str = COMPLETE,
    launched_at: datetime | None = None,
) -> DetonationResult:
    """Turn a finished observation into a result, or into an honest failure.

    The distinction this draws is the important one. An app that was watched and
    did nothing, and an app that was never actually watched, both produce an
    empty list of events. Reported the same way, the second would tell an
    investigator that a harvester is harmless. So when the instrumentation
    itself failed and saw nothing, the run is a failure, and the report keeps
    its statement that the file's behaviour was never observed.
    """
    # Offsets run from the launch, because that is the instant the reader cares
    # about: "three seconds after the app opened", not three seconds after a
    # virtual phone was switched on.
    events = events_from_payloads(payloads, launched_at or started_at)

    if errors and not events:
        return DetonationResult.failed(
            platform=ANDROID,
            engine=FRIDA,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            error=(
                "the instrumentation did not run, so nothing about this app's "
                "behaviour was observed: " + "; ".join(errors)
            ),
            artifacts=artifacts,
        )

    partial = (
        f" Some hooks reported errors and their behaviour may be missing: "
        f"{'; '.join(errors)}"
        if errors
        else ""
    )

    return DetonationResult(
        platform=ANDROID,
        engine=FRIDA,
        status=status,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        events=events,
        artifacts=artifacts,
        coverage=f"{conditions}{partial}",
    )


def _moment(timestamp, started_at: datetime) -> datetime:
    """The wall-clock time a hook reported, or the start of the run.

    An unusable timestamp falls back rather than dropping the event: that
    something happened is worth more than exactly when, and the offset it gets
    (zero) understates rather than invents.
    """
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        return started_at
    try:
        return datetime.fromtimestamp(timestamp / 1000, timezone.utc)
    except (ValueError, OverflowError, OSError):
        return started_at


def _whole_number(value) -> int | None:
    """A non-negative count from a hook, or None when there is not one.

    Used for both byte totals and row counts. A negative or non-numeric value
    means the hook could not measure it, which is reported as absent rather than
    guessed at or flattened to zero — for a row count those mean very different
    things.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value) if value >= 0 else None


# --------------------------------------------------------------------------
# The sandbox itself
# --------------------------------------------------------------------------


def detonate_apk(
    apk_path: Path | str,
    *,
    sdk_root: Path | str | None = None,
    avd_home: Path | str | None = None,
    avd: str = DEFAULT_AVD,
    frida_server: Path | str | None = None,
    dwell_seconds: int = DEFAULT_DWELL_SECONDS,
    boot_timeout_seconds: int = DEFAULT_BOOT_TIMEOUT_SECONDS,
    artifacts_dir: Path | str | None = None,
    decoy_messages: int = 0,
    on_progress=None,
) -> DetonationResult:
    """Install and run one APK in the emulator, and report what it did."""
    apk_path = Path(apk_path)
    started_at = datetime.now(timezone.utc)

    def say(message: str) -> None:
        """Report a stage as it starts.

        An Android detonation takes minutes, most of it booting a virtual phone.
        Without this the interface has nothing true to show and would be reduced
        to animating a bar, which tells the person watching nothing about
        whether anything is actually happening.
        """
        if on_progress is None:
            return
        try:
            on_progress(message)
        except Exception:  # noqa: BLE001 - reporting never breaks a run
            pass

    def failure(error: str, artifacts: dict | None = None) -> DetonationResult:
        return DetonationResult.failed(
            platform=ANDROID,
            engine=FRIDA,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            error=error,
            artifacts=artifacts or {},
        )

    if not apk_path.is_file():
        return failure(f"there is no file at {apk_path}")

    try:
        tools = _Tools.locate(sdk_root)
    except FileNotFoundError as exc:
        return failure(str(exc))

    manifest = analyze_apk(apk_path)
    package = manifest.package
    if not package:
        return failure(
            "the APK's package name could not be read, so the app cannot be launched"
        )

    emulator = _Emulator(tools, avd=avd, avd_home=avd_home)
    artifacts: dict[str, str] = {}

    try:
        capture = _capture_path(artifacts_dir, apk_path)
        if capture is not None:
            artifacts["pcap"] = str(capture)

        say("Starting a clean virtual phone")
        emulator.start(capture)
        if not emulator.wait_for_boot(boot_timeout_seconds):
            return failure(
                f"the emulator did not finish booting within "
                f"{boot_timeout_seconds} seconds",
                artifacts,
            )

        say("Putting decoy messages on the phone")
        seeded = emulator.seed_decoy_messages(decoy_messages)

        say("Installing the app")
        installed = emulator.install(apk_path)
        if installed is not None:
            return failure(f"the app could not be installed: {installed}", artifacts)

        say("Granting the permissions the app asks for")
        granted = emulator.grant(package, manifest.dangerous_permissions)

        say("Attaching behaviour monitors")
        started = emulator.start_frida_server(frida_server)
        if started is not None:
            return failure(started, artifacts)

        return _observe(
            emulator,
            package=package,
            started_at=started_at,
            dwell_seconds=dwell_seconds,
            artifacts=artifacts,
            conditions=_conditions(dwell_seconds, seeded, granted),
            say=say,
        )
    except Exception as exc:  # noqa: BLE001 - a sandbox reports, it never raises
        return failure(f"{type(exc).__name__}: {exc}", artifacts)
    finally:
        # An emulator left running holds gigabytes of RAM and blocks the next
        # detonation, which is why this is unconditional.
        emulator.stop()


def _observe(
    emulator: "_Emulator",
    *,
    package: str,
    started_at: datetime,
    dwell_seconds: int,
    artifacts: dict[str, str],
    conditions: str = "",
    say=lambda message: None,
) -> DetonationResult:
    """Launch the app under Frida, exercise it, and gather what the hooks saw."""
    import frida

    messages: list = []
    lock = threading.Lock()

    def on_message(message, _data):
        # Everything is kept, including script faults. Which is which is decided
        # later, by `split_messages`, so that a failing hook cannot vanish here.
        with lock:
            messages.append(message)

    device = frida.get_device_manager().add_remote_device(emulator.frida_address)
    pid = device.spawn([package])
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT.read_text())
    script.on("message", on_message)
    script.load()
    # The app is spawned suspended and the hooks are installed before it runs a
    # single instruction, so nothing it does at startup is missed. This is the
    # instant it actually begins, and every offset in the timeline is measured
    # from here.
    launched_at = datetime.now(timezone.utc)
    say("Opening the app and watching what it does")
    device.resume(pid)

    status = COMPLETE
    try:
        # Fraud apps do nothing until a screen is touched; the harvest starts
        # once the victim taps through the fake login. Monkey supplies taps that
        # no one has to sit and perform.
        emulator.drive(package)
        say(f"Letting it run for {dwell_seconds} seconds")
        time.sleep(dwell_seconds)
    finally:
        try:
            session.detach()
        except Exception:  # noqa: BLE001 - the app may already be gone
            status = TIMEOUT

    with lock:
        collected = list(messages)

    logcat = emulator.save_logcat(artifacts)
    if logcat:
        artifacts["logcat"] = logcat

    say("Collecting what was seen")
    payloads, errors = split_messages(collected)
    return result_from_observation(
        started_at=started_at,
        payloads=payloads,
        errors=errors,
        artifacts=artifacts,
        conditions=conditions,
        status=status,
        launched_at=launched_at,
    )


def _conditions(dwell_seconds: int, seeded: int, granted: list[str]) -> str:
    """The conditions the observations were made under.

    An observation is only worth what the reader knows about how it was
    obtained. Two things here would otherwise mislead: the sandbox grants the
    permissions the app asks for rather than waiting for a person to tap
    "Allow", and the phone is seeded with decoy messages so that "read the
    inbox" produces a count. Both make the app's behaviour visible, and both
    have to be on the record, because neither is what would happen on a real
    victim's phone unaided.
    """
    parts = [
        f"The app ran under instrumentation for {dwell_seconds} seconds while its "
        f"screens were exercised automatically."
    ]
    if granted:
        parts.append(
            f"The sandbox granted the {len(granted)} permission(s) the app "
            f"requested, rather than waiting for a person to accept them, so that "
            f"what the app does with them could be observed."
        )
    if seeded:
        parts.append(
            f"The phone was seeded with {seeded} decoy text message(s) before the "
            f"app was started; it held no real personal data at any point."
        )
    parts.append(
        "Behaviour that only begins later, or that waits for a real person, would "
        "not appear here. Nothing above rules out what was not seen."
    )
    return " ".join(parts)


def _capture_path(artifacts_dir, apk_path: Path) -> Path | None:
    if artifacts_dir is None:
        return None
    directory = Path(artifacts_dir)
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{apk_path.stem}.pcap"


class _Tools:
    """Where the SDK's binaries are on this machine."""

    def __init__(self, adb: Path, emulator: Path):
        self.adb = adb
        self.emulator = emulator

    @classmethod
    def locate(cls, sdk_root: Path | str | None) -> "_Tools":
        if sdk_root is not None:
            root = Path(sdk_root)
            adb = root / "platform-tools" / "adb"
            emulator = root / "emulator" / "emulator"
            missing = [str(p) for p in (adb, emulator) if not p.is_file()]
            if missing:
                raise FileNotFoundError(
                    "the Android SDK is incomplete; not found: " + ", ".join(missing)
                )
            return cls(adb, emulator)

        found = {name: shutil.which(name) for name in ("adb", "emulator")}
        missing = [name for name, path in found.items() if path is None]
        if missing:
            raise FileNotFoundError(
                "the Android SDK is not installed; not on PATH: " + ", ".join(missing)
            )
        return cls(Path(found["adb"]), Path(found["emulator"]))


class _Emulator:
    """One throwaway phone, driven over adb."""

    FRIDA_PORT = 27042

    def __init__(self, tools: _Tools, *, avd: str, avd_home=None):
        self.tools = tools
        self.avd = avd
        self.avd_home = Path(avd_home) if avd_home else None
        self.process: subprocess.Popen | None = None

    @property
    def frida_address(self) -> str:
        return f"127.0.0.1:{self.FRIDA_PORT}"

    def _env(self) -> dict:
        env = dict(os.environ)
        if self.avd_home is not None:
            env["ANDROID_AVD_HOME"] = str(self.avd_home)
        return env

    def start(self, capture: Path | None) -> None:
        arguments = [
            str(self.tools.emulator),
            "-avd",
            self.avd,
            "-no-window",
            "-no-audio",
            "-no-boot-anim",
            # Every run starts from a factory-fresh phone. Without this a sample
            # would inherit whatever the previous one installed or wrote.
            "-no-snapshot",
            "-wipe-data",
            "-gpu",
            "swiftshader_indirect",
        ]
        if capture is not None:
            # The emulator writes the pcap itself, so no privileged capture tool
            # is needed on the host.
            arguments += ["-tcpdump", str(capture)]

        self.process = subprocess.Popen(
            arguments,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._env(),
        )

    def _adb(self, *arguments: str, timeout: int = 120) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.tools.adb), *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=self._env(),
        )

    def wait_for_boot(self, timeout_seconds: int) -> bool:
        deadline = time.monotonic() + timeout_seconds
        self._adb("wait-for-device", timeout=timeout_seconds)
        while time.monotonic() < deadline:
            finished = self._adb("shell", "getprop", "sys.boot_completed", timeout=30)
            if finished.stdout.strip() == "1":
                return True
            time.sleep(3)
        return False

    def install(self, apk_path: Path) -> str | None:
        """Install the sample. Returns None on success, or the reason it failed."""
        result = self._adb("install", "-r", "-t", str(apk_path), timeout=300)
        output = f"{result.stdout}{result.stderr}".strip()
        if result.returncode != 0 or "Success" not in output:
            return output or "adb install gave no reason"
        return None

    def seed_decoy_messages(self, count: int) -> int:
        """Put fabricated text messages on the phone before the app is started.

        A factory-fresh phone has an empty inbox, so a harvester reads nothing
        and the timeline shows an app doing no harm. Seeding gives the read
        something to find and turns the observation into a number, which is the
        difference between "read the inbox" and "read 12 messages". The content
        is invented and the phone is destroyed afterwards.

        Returns how many were accepted.
        """
        seeded = 0
        for index in range(count):
            result = self._adb(
                "emu",
                "sms",
                "send",
                f"+9199000{index:05d}",
                f"Decoy message {index + 1} for sandbox observation.",
                timeout=30,
            )
            if result.returncode == 0:
                seeded += 1
        return seeded

    def grant(self, package: str, permissions: list[str]) -> list[str]:
        """Grant the permissions the app asked for.

        A real victim taps "Allow" because the app has just told them it is
        their bank. Waiting for a tap that no one is there to make would leave
        the harvest unobserved and the report empty. What was granted is
        reported alongside the findings, so the conditions are never implicit.
        """
        granted = []
        for permission in permissions:
            result = self._adb("shell", "pm", "grant", package, permission, timeout=30)
            if result.returncode == 0 and not result.stderr.strip():
                granted.append(permission)
        return granted

    def start_frida_server(self, frida_server: Path | str | None) -> str | None:
        """Push and run frida-server as root. Returns None on success."""
        if frida_server is None:
            return "no frida-server binary was configured for the sandbox"
        binary = Path(frida_server)
        if not binary.is_file():
            return f"there is no frida-server binary at {binary}"

        # A google_apis image allows this; a playstore image does not, which is
        # why the AVD must not be built from a playstore system image.
        self._adb("root", timeout=60)
        time.sleep(3)
        self._adb("wait-for-device", timeout=60)

        pushed = self._adb("push", str(binary), "/data/local/tmp/frida-server", timeout=300)
        if pushed.returncode != 0:
            return f"frida-server could not be copied to the device: {pushed.stderr.strip()}"

        self._adb("shell", "chmod", "755", "/data/local/tmp/frida-server", timeout=60)
        subprocess.Popen(
            [str(self.tools.adb), "shell", "/data/local/tmp/frida-server"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._env(),
        )
        self._adb("forward", f"tcp:{self.FRIDA_PORT}", f"tcp:{self.FRIDA_PORT}", timeout=60)
        time.sleep(5)
        return None

    def drive(self, package: str) -> None:
        """Tap around the app so behaviour behind the first screen is reached."""
        try:
            self._adb(
                "shell", "monkey", "-p", package, "--throttle", "300", "-v", "300",
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            # Driving the UI is best-effort; whatever the hooks already saw
            # still counts.
            pass

    def save_logcat(self, artifacts: dict) -> str | None:
        destination = artifacts.get("pcap")
        if destination is None:
            return None
        path = Path(destination).with_suffix(".logcat.txt")
        try:
            result = self._adb("logcat", "-d", timeout=60)
        except subprocess.TimeoutExpired:
            return None
        path.write_text(result.stdout, errors="replace")
        return str(path)

    def stop(self) -> None:
        try:
            self._adb("emu", "kill", timeout=30)
        except Exception:  # noqa: BLE001 - it may never have started
            pass
        if self.process is not None:
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()


def hook_script_source() -> str:
    """The instrumentation, as it will be loaded into the sample's process."""
    return HOOK_SCRIPT.read_text()


__all__ = [
    "ANDROID",
    "FRIDA",
    "HOOK_SCRIPT",
    "detonate_apk",
    "event_from_payload",
    "events_from_payloads",
    "hook_script_source",
]
