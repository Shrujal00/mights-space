# Dynamic analysis: what was built, and what bit

Companion to `dynamic-analysis-plan.md`. That document is the design; this one
records what the implementation actually ran into, so the next person does not
rediscover it.

Phases 0–5 are done. Phase 6 (UI) is untouched, as the plan instructed.

---

## Gotchas that cost real time

**Frida 17 does not ship the Java bridge.** This is the big one. `frida` 17.x
removed the bundled Java/ObjC bridges from the agent runtime, so a hook script
calling `Java.perform` dies with `ReferenceError: 'Java' is not defined`. The
app then runs completely uninstrumented and the sandbox reports *zero events* —
which reads exactly like a well-behaved app. `requirements.txt` pins
`frida==16.7.19` for this reason. The `frida-server` binary pushed to the device
must be the same version.

Moving to 17 later means bundling `frida-java-bridge` with `frida-compile`,
which adds a Node build step to a Python project and a build artifact to an
air-gapped deployment. It was not worth it.

**Speakeasy warns twice, and the second one truncates traces silently.** The
plan noted the `pkg_resources` warning at import. There is a second: Speakeasy
calls the deprecated `datetime.utcnow()` *during emulation*. With
`filterwarnings = error` that surfaces as an exception mid-run, and the trace
comes back with 0 API calls instead of 410. Both are contained by
`_third_party_warnings_contained()` in `sandbox/windows_speakeasy.py`, which
wraps the emulation calls, not just the import.

**One `ContentResolver.query` by the app fires the hook two or three times.**
Android implements the short `query` overloads by calling the longer ones, and
all overloads are hooked. Uncollapsed, a single read of the inbox became three
observations and three exfiltration findings. `_collapse_echoes` in
`sandbox/android.py` drops exact repeats within 50 ms; anything further apart,
or with a different row count, is kept as a genuine second read.

**Offsets must run from app launch, not sandbox start.** Booting the emulator
takes about 40 seconds. Measured from the start of the run, an app that
harvested immediately appeared to have waited 40 seconds. Offsets are now taken
from the instant `device.resume(pid)` is called.

**avdmanager follows `XDG_CONFIG_HOME`.** On this machine the AVD landed in
`~/.config/.android/avd`, not `~/.android/avd`, and the emulator will not find
it without `ANDROID_AVD_HOME`. Check `avdmanager list avd` for the real path;
the `ANDROID_AVD_HOME` setting exists for this.

**`tcpdump` and `mitmproxy` were never installed** — they need root, which was
not available. Host `tcpdump` turned out to be unnecessary: the emulator's own
`-tcpdump <file>` flag writes a pcap of the VM's traffic with no privileged
tooling. `mitmproxy` for TLS interception is still outstanding.

---

## Decisions worth knowing about

**No migration tool was needed.** Everything added is a *new table*
(`detonation_runs`, `behavior_events`), and `create_all()` creates missing
tables. No column was added to an existing table, so no `ALTER TABLE` and no
Alembic. That stops being true the moment something is added to `samples`.

**The sandbox grants permissions and seeds decoy messages.** A factory-fresh
emulator has an empty inbox and nobody to tap "Allow", so an unaided run
observes a harvester doing nothing. The sandbox grants the permissions the app
declares and seeds fabricated messages. Both change what would happen on a real
phone, so both are stated in the run's `coverage` text and printed in the
report — the conditions of an observation are never left implicit.

**A read returning zero rows is not exfiltration.** An app that queries an empty
contacts list and then transmits has not stolen contacts. `correlate()` skips
data-access events whose `record_count` is 0. A count of `None` (unavailable,
e.g. reading the IMEI) is *not* treated as zero and still pairs.

**Instrumentation failure is a failed run, not a quiet one.** If the hook script
does not load, the run comes back `failed` with the reason, and the report keeps
its statement that the file's behaviour was never observed. An empty timeline
and an unobserved app must never look the same.

**Counts and byte totals are carried as numbers, never parsed back out of
prose.** `size_bytes` and `record_count` are separate fields for this reason. A
figure in a police report has to come from the measurement.

---

## Verifying it

Hermetic suite, no emulator required:

```
cd backend && .venv/bin/python -m pytest -q      # 366 passing
```

Live Android detonation, against the purpose-built mock sample:

```
backend/tests/fixtures/mock_apk/build.sh         # rebuild the APK (needs the SDK)
```

The mock sample (`tests/fixtures/mock_apk/`) reads SMS, contacts and call log,
then POSTs to loopback three seconds later. A good run looks like:

```
+  0.05s  process      started  the application
+  0.46s  data-access  read     SMS inbox      2 records
+  0.49s  data-access  read     contacts       0 records
+  3.61s  network      opened   http://10.0.2.2:8099/collect

EXFILTRATION FINDINGS: 1
  2 records from SMS inbox -> http://10.0.2.2:8099/collect (3152 ms later, strong)
```

Note the single finding: the two reads that returned nothing are on the
timeline but are correctly not called theft.

---

## Known gaps

- **Byte counts on Android are not captured.** `java.net.URL.openConnection`
  gives the destination but not the size of the body, so findings show the
  destination and the delay with `bytes_sent` absent. Hooking the connection's
  output stream would close this.
- **Only 2 of 12 seeded messages were readable** in the live run. The mechanism
  works; the seeding is not yet reliable enough to produce a large count.
- **No TLS interception.** `mitmproxy` is not installed and its CA is not in the
  emulator, so HTTPS bodies are opaque. Destination and timing are still
  observed, which is what the exfiltration pairing rests on.
- **The plan's second validation step — detonating a real sample from
  `~/Downloads/Andorid Malware(1)/` — has not been done.** The emulator has
  unrestricted network access, so running live malware would let it reach its
  real command-and-control infrastructure from this network. That needs either a
  deliberate decision or an offline/INetSim network mode first.
