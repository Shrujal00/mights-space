"""Choosing a sandbox for a sample, and staying out of the way when there is none.

One object answers three questions: which engine suits a sample, whether this
deployment can run it at all, and whether it should be run automatically.
Keeping that behind a single seam means the upload path never grows a chain of
platform checks, and the whole of dynamic analysis can be switched off — or
stubbed in a test — in one place.

Running a file and reading it are deliberately separate. `applies` governs the
automatic path, which is off unless a deployment opts in; `can_run` governs the
button an investigator presses. A deployment can therefore be able to detonate
on request without detonating everything that is uploaded.
"""

from pathlib import Path

from ..analysis.behavior import DetonationResult
from .android import detonate_apk
from .windows_speakeasy import detonate_pe

ANDROID = "android"
WINDOWS = "windows"


class Detonator:
    """Runs a sample in whichever sandbox suits it, if any."""

    def __init__(self, settings):
        self.settings = settings

    def engine_for(self, result) -> tuple[str | None, str]:
        """The platform and engine for this sample, or (None, "")."""
        if self._is_apk(result):
            return ANDROID, "frida"
        if self._is_pe(result):
            return WINDOWS, "speakeasy"
        return None, ""

    def can_run(self, result) -> bool:
        """Whether this deployment could run this sample if asked.

        The Windows emulator needs nothing installed. Android needs an SDK and a
        matching frida-server, and saying so up front is better than booting an
        emulator to discover it.
        """
        platform, _ = self.engine_for(result)
        if platform is None:
            return False
        if platform == WINDOWS:
            return True
        return bool(self.settings.frida_server_path and self.settings.android_sdk_root)

    def applies(self, result) -> bool:
        """Whether this sample should be detonated automatically on upload.

        Off unless the deployment opts in. Detonation executes the sample and
        takes minutes, and that should not be a surprise consequence of
        uploading a file.
        """
        return bool(self.settings.dynamic_analysis_enabled) and self.can_run(result)

    def run(self, path: Path, result, on_progress=None) -> DetonationResult | None:
        platform, _ = self.engine_for(result)
        if platform is None:
            return None

        if platform == ANDROID:
            settings = self.settings
            return detonate_apk(
                path,
                sdk_root=settings.android_sdk_root,
                avd_home=settings.android_avd_home,
                avd=settings.android_avd,
                frida_server=settings.frida_server_path,
                dwell_seconds=settings.detonation_dwell_seconds,
                boot_timeout_seconds=settings.detonation_boot_timeout_seconds,
                artifacts_dir=settings.detonation_artifacts_dir,
                decoy_messages=settings.detonation_decoy_messages,
                on_progress=on_progress,
            )

        return detonate_pe(path, on_progress=on_progress)

    @staticmethod
    def _is_apk(result) -> bool:
        return any(leaf.apk is not None for leaf in result.files)

    @staticmethod
    def _is_pe(result) -> bool:
        # Only when there is no APK: an APK is a ZIP and may contain a bundled
        # Windows binary, but the thing to run is the app.
        return not Detonator._is_apk(result) and any(
            leaf.pe is not None for leaf in result.files
        )
