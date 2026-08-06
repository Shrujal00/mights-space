# Dynamic analysis: Android sandbox + Windows emulation

**Handoff plan.** The executing model has none of the context in which this was
written. Read the whole document before touching code.

---

## Context

`mights-space` is a static malware triage tool for **Surat Cyber Police**. An
investigator uploads a file from a seized device and gets a plain-English verdict
they can put in a case file.

**Static analysis is complete** (233 tests passing). Covered: hashing, YARA (750
vendored signature-base rules), Windows PE inspection, Android APK manifest and
permission analysis, IOC and suspicious-string extraction, MITRE ATT&CK mapping,
five threat-intel providers, CSV/STIX/Word export, and an Ollama-written narrative.

**Dynamic analysis is entirely missing** — Section II of the problem statement.
Investigators need to see what a sample actually *does*: what data it reads and
where it sends it. That is this plan.

The caseload is Indian fraud: loan-app extortion, fake e-Challan/RTO notices,
light-bill scams, bank KYC phishing. **Overwhelmingly Android.** Real samples in
`~/Downloads/Andorid Malware(1)/` demonstrate the pattern — apps named "YONO SBI"
with package `com.facebook.smsrecevies`, harvesting SMS for OTP theft.

**The demo sentence this whole plan exists to produce:**

> "This app read the victim's 247 SMS messages at 14:03:22 and sent 34 KB to
> 185.244.25.14 three seconds later."

---

## Existing architecture (do not re-derive)

```
backend/app/
  main.py            create_app() factory; app.state holds scanner/enricher/narrator
  config.py          pydantic-settings; every key optional
  db.py              Database wrapper; NullPool for SQLite
  models.py          SQLAlchemy 2.0 typed models
  api/samples.py     upload, report, exports; _serialize() is the shared shape
  analysis/
    pipeline.py      analyze_sample() orchestrator; LeafReport per file
    extract.py       archive expansion; APK detected BEFORE unzip
    pe_analysis.py   Windows PE          apk_analysis.py  Android APK
    attack_map.py    imports → ATT&CK    android_map.py   permissions → ATT&CK
    apk_signals.py   impersonation tells
    ioc_extract.py   URLs/IPs/domains, heavily filtered
    strings_extract.py  extract_strings() + select_notable()
    summary.py       summarize() → verdict + narrative
    narrative.py     Ollama writer
    export/          csv_export, stix_export, docx_export
```

**Patterns to follow, not reinvent:**

- `Technique` (`attack_map.py:14`) — frozen dataclass, reused by `android_map.py`.
  **Reuse it for dynamic findings too.**
- `ProviderResult` (`reputation/base.py`) — status/detail/data. Good model for any
  operation that can fail without killing the report.
- Analysers are **pure functions separated from I/O adapters** (see
  `shannon_entropy`/`assess_packing` vs `analyze_pe`). Keep this — it is why the
  test suite is fast and meaningful.
- Every analyser degrades to a partial report rather than raising. `analyze_apk()`
  is the reference implementation.

---

## Non-negotiable invariants

**1. The "never executed" promise must become conditional, not deleted.**

`summary.py:37` defines `NOT_EXECUTED_NOTE`, appended to every narrative at
`summary.py:264`. `tests/test_summary.py:89` asserts `"was not run"` appears.
Once samples are detonated this is false for some reports.

Do **not** delete it. Make it conditional on whether dynamic analysis ran, and
scope the existing test to static-only reports. A report that ran dynamically
must state that it was executed in a contained sandbox, and when.

**2. Static and dynamic findings must never be conflated.**

`models.py:134` already has the hook: `basis` defaults to `"static-import"`.
Android static uses `"static-manifest"`. Dynamic findings use
**`"dynamic-observed"`**. The report must render these differently:

```
Capability (from reading the code):  can read text messages
Observed (sandbox, 14:03:22):        read 247 text messages
```

Getting this wrong makes the report attackable in court. One "observed" claim
that was actually an inference discredits the whole document.

**3. Never claim a file is safe.** Enforced by
`tests/test_summary.py::test_a_clean_result_never_claims_the_file_is_safe`.

**4. No provider/sandbox failure may cost the report.** If detonation fails, the
static report still stands.

---

## Phase 0 — Environment (Arch Linux)

Current state, verified:

| | Status |
|---|---|
| `/dev/kvm`, VT-x | present |
| `~/Android/Sdk/emulator/emulator` | present |
| `~/Android/Sdk/cmdline-tools` | **MISSING** — needed for `sdkmanager` |
| system-images, AVDs | none |
| `adb`, `fastboot` | installed |
| `frida`, `tcpdump`, `mitmproxy` | **not installed** |
| VirtualBox `Win11_Sandbox` | exists, snapshots: `clean` → `clean-hardened` → `clean-hardened-agent` |
| libvirt `Windows-10` | exists, no snapshots |

**Steps:**

1. Install cmdline-tools into `~/Android/Sdk/cmdline-tools/latest/`, then:
   ```
   sdkmanager "system-images;android-33;google_apis;x86_64"
   avdmanager create avd -n triage -k "system-images;android-33;google_apis;x86_64"
   ```
   **`google_apis`, NOT `google_apis_playstore`.** PlayStore images have a locked
   `/system` and `adb root` fails — which kills frida-server.

2. `pip install frida-tools` (host). Download matching `frida-server` for
   `android-x86_64`, push to `/data/local/tmp/`, run as root.

3. System packages: `tcpdump`, `mitmproxy`.

4. Verify: `emulator -avd triage -no-window -no-snapshot` boots, `adb root`
   succeeds, `frida-ps -U` lists processes.

**VT-x contention:** VirtualBox and KVM fight over the CPU extensions. Not an
issue in practice because detonations are serialised by design (one sample per
sandbox). Do not run a Windows VM and the emulator concurrently.

**RAM:** host has 15 GB. Base stack ~6 GB + one sandbox 2–8 GB fits; two
concurrent sandboxes do not. This reinforces serialisation.

---

## Phase 1 — Event model and schema (foundation, do this first)

Everything else depends on this. **Both platforms write the same shape.**

New `backend/app/analysis/behavior.py`:

```python
@dataclass(frozen=True)
class BehaviorEvent:
    at: datetime          # absolute
    offset_ms: int        # since detonation start — what the report shows
    category: str         # process | file | network | data-access | registry | crypto
    action: str           # "read", "sent", "started", "wrote"
    target: str           # "SMS inbox", "185.244.25.14:443", "C:\...\run.exe"
    detail: str           # "247 records"
    source: str           # frida | speakeasy | sysmon | pcap
```

New models in `models.py`:

- `DetonationRun` — sample_id, platform (`android`/`windows`), engine
  (`frida`/`speakeasy`), status (`queued`/`running`/`complete`/`failed`/`timeout`),
  started_at, finished_at, error, artifact paths.
- `BehaviorEventRow` — run_id + the fields above.

Extend `Sample.status` beyond `queued`/`complete`/`failed` (see
`api/samples.py:101`) with `detonating`. On app startup, mark any run left
`running` as `failed` ("interrupted by restart") — otherwise a crash orphans it.

**⚠ No migration tool.** `create_all()` only creates missing *tables*, never adds
columns to existing ones. New columns on existing tables require a manual
`ALTER TABLE` on any populated database, or it fails at runtime with "no such
column". Alembic is already an installed dependency (pulled in by androguard) —
consider adopting it in this phase.

**Also:** foreign keys have no `ON DELETE CASCADE`; cascade is ORM-level only.
Any raw-SQL deletion must remove children first (see
`backend/scripts/reset_cases.py` for the existing pattern).

---

## Phase 2 — Android dynamic (highest value; build second)

New `backend/app/sandbox/android.py`.

**Flow:** boot AVD (`-no-snapshot -wipe-data`, `-http-proxy` at mitmproxy) →
`adb install` → `adb root` → start frida-server → spawn app under Frida with the
hook script → drive UI with `adb shell monkey` → collect → kill emulator.

**Frida hooks** (`backend/app/sandbox/hooks/android.js`) — hook these and emit one
`BehaviorEvent` per call:

| Target | Event |
|---|---|
| `ContentResolver.query` on `content://sms` | data-access, "read SMS", row count |
| `content://contacts` | data-access, "read contacts", row count |
| `content://call_log` | data-access, "read call log" |
| `SmsManager.sendTextMessage` | network, "sent SMS", destination |
| `LocationManager.getLastKnownLocation` | data-access, "read location" |
| `TelephonyManager.getDeviceId/getSubscriberId` | data-access, device identity |
| `HttpURLConnection`, `OkHttpClient`, `Retrofit` | network, URL + byte count |
| `DexClassLoader` | process, "loaded code at runtime" |
| `File` writes under `/data/data/` | file |

**Record row counts.** "Read 247 SMS messages" is far stronger evidence than
"read SMS".

**Network:** mitmproxy with its CA installed in the emulator for TLS; tcpdump for
raw. Cert-pinned apps will fail TLS interception — fall back to SNI/metadata,
which is explicitly a bonus objective in the spec.

**Do not need INetSim initially.** A recorded *connection attempt* to a C2 is the
exfiltration mapping. Add fake-internet later to make evasive samples talk.

---

## Phase 3 — Windows via Speakeasy (no VM)

New `backend/app/sandbox/windows_speakeasy.py`.

**Verified working** on this stack: `speakeasy-emulator` 1.5.11 on Python 3.13
traced 410 API calls plus file access from the benign PE fixture.

Speakeasy emulates PE instructions in a Unicorn CPU emulator against a synthetic
Windows kernel. The code never executes natively — there is no host to escape to.
This is *more* defensible than a VM and the report should say so precisely.

```python
se = speakeasy.Speakeasy()
module = se.load_module(path)
se.run_module(module)           # wrap in try/except — emulation stops early often
report = se.get_report()        # entry_points[].apis / network_events / file_access
```

Map `report["entry_points"][*]["apis"]` to `BehaviorEvent`s, reusing the existing
`TECHNIQUE_SIGNATURES` in `attack_map.py` for classification — the API names are
the same ones the static import mapper already knows.

**Two hard requirements:**

1. **Pin `setuptools<81` in `requirements.txt`.** unicorn 1.0.2 imports
   `pkg_resources`, removed in setuptools 81. Without the pin, import fails.
2. **Import speakeasy lazily, inside the function.** It emits a `pkg_resources`
   DeprecationWarning at import, and `pytest.ini` sets `filterwarnings = error` —
   a module-level import would fail the entire 233-test suite.

**Coverage is partial** — packed samples and unsupported APIs cause early exit.
Record how far it got. `Win11_Sandbox` (already hardened, with snapshots) remains
plan B if coverage disappoints; that path would use `VBoxManage snapshot restore`
+ `guestcontrol` + **Sysmon** in the guest rather than a custom hooking agent.

---

## Phase 4 — Correlation and exfiltration mapping

New `backend/app/analysis/exfiltration.py`. **This is the payoff.**

Pair each `data-access` event with the next `network` event within a time window
(start ~5s, tune against real samples). Emit:

```python
@dataclass
class ExfiltrationFinding:
    what: str          # "247 SMS messages"
    where: str         # "185.244.25.14:443"
    when: datetime
    gap_ms: int
    bytes_sent: int | None
    confidence: str    # strong | probable
```

Enrich the destination through the **existing** `Enricher`
(`analysis/enrichment.py`) — ThreatFox/AbuseIPDB already work and are wired.

Feed findings into `summarize()` as a new signal generator alongside
`_destination_signals`. Observed exfiltration to a known C2 is the strongest
verdict evidence the system can produce and should raise to `malicious`.

---

## Phase 5 — Reports

Two reports, as requested:

- **Static** — available immediately after upload (already exists).
- **Dynamic** — available after detonation.
- Both merge into the Word document (`export/docx_export.py`).

New docx sections: `OBSERVED BEHAVIOUR` (the timeline) and
`DATA SENT OUT OF THE DEVICE` (exfiltration findings). Follow the existing
`_android()` helper's structure.

**AI layer** — two tiers, kept visually separate:

```
VERIFIED FINDINGS      deterministic, court-ready
AI ANALYST ASSESSMENT  free to correlate and hypothesise; marked machine-written
```

The model may reason freely in tier 2 but must **never** originate a timestamp,
hash, or IP — those render from data. Extend the existing `narrative.py`
`build_facts()` to include behaviour events; keep its guardrail prompt.

---

## Phase 6 — UI (later, after dynamic works)

Do not build this until Phases 1–5 land. Notes so the design is not re-litigated:

**Existing design system** (`frontend/src/styles/tokens.css`) is **strictly
achromatic — zero hue**, deliberately. The backend refuses to call a file safe; a
traffic-light UI would undo that because green reads as "cleared". Severity is
carried by fill and inversion: malicious inverts to solid white, suspicious is
outlined, unknown is a hairline. **Do not introduce colour.**

Type: Archivo (display, `font-stretch` 112–118%), IBM Plex Sans (body), IBM Plex
Mono (data). Self-hosted via `@fontsource` — a CDN would break air-gapped use.

**What to add:**

1. **Behaviour timeline** — the report's centrepiece. Vertical, monospace
   timestamps, one row per event, category as a mono label. Data-access and
   network events adjacent in time should be visually linked — that pairing *is*
   the exfiltration finding.
2. **Detonation status** — replaces polling silence. The existing
   `ReadingSequence.tsx` already does this for static; extend the same pattern.
3. **Static vs observed** — distinct treatment, per invariant 2. Suggest a mono
   `OBSERVED` marker with the offset; never merge the two lists.

The user has shown a reference dashboard mockup (sidebar, sandbox status cards,
stat tiles). **Much of it depicts data this system cannot produce** — risk scores
out of 100, radar "behavior summaries", per-connection counts. Build only panels
backed by real data; a fabricated risk score is indefensible in a police report.

---

## Gotchas discovered in this session

- **APK is a ZIP.** `extract.py` must detect APKs *before* unzipping or the
  manifest and DEX are destroyed. Already handled — don't regress it.
- **APK strings come from the DEX string pool**, not raw bytes (the DEX is
  deflated). See `apk_analysis._read_dex`.
- **`pkill -f "uvicorn app.main"` self-matches** the wrapper shell and kills it.
  Use a separate command from the one that starts the server.
- **`backend/.env` `DATABASE_URL` points at `db:5432`**, a Compose hostname that
  does not resolve on the host. Local runs need an override.
- **Never use live malware as a test fixture** — stated in
  `tests/fixtures/README.md`. Real samples in `~/Downloads` are for manual
  validation only. Test pure logic; keep the suite hermetic.

---

## Verification

**Per phase:**

1. **Phase 1** — `BehaviorEvent` round-trips through the DB; a killed process
   leaves no run stuck in `running`.
2. **Phase 2** — detonate a purpose-built mock APK that requests
   SMS/contacts/location and POSTs to a local server. **Build this fixture; do not
   demo with live malware** — real samples detect emulators and play dead, and a
   controlled sample exercises every code path reproducibly. Then validate against
   `~/Downloads/Andorid Malware(1)/SBI YONO REWARDZ.apk`.
3. **Phase 3** — `speakeasy` traces the benign fixture
   (`tests/fixtures/benign_pe32.exe`, known good: 410 API calls); confirm the full
   suite still passes, proving the lazy import worked.
4. **Phase 4** — synthetic event sequences produce the expected pairing; window
   boundaries tested both sides.
5. **Phase 5** — Word report contains both an observed timeline and the
   not-executed statement scoped correctly.

**Always:** `cd backend && .venv/bin/python -m pytest -q` — currently **233
passing**. No phase may reduce that number.

**End to end:** `./start.sh`, upload an APK at `localhost:5173`, watch it move
`queued → detonating → complete`, confirm the report shows observed behaviour with
timestamps and an exfiltration destination, and download the Word report.
