# Deployment and packaging

How this system is installed, what hardware it needs, and how it reaches the
people who use it.

Status as of 6 August 2026: static analysis is complete and in use. Dynamic
analysis is designed but not yet built. Packaging has not started — this document
records the decisions so the work can be done once, at the right time.

---

## 1. The deployment model

The system is deployed as **two different products**, because it has two
different kinds of user with almost nothing in common.

| | Field build | Analysis server |
|---|---|---|
| Used by | Station officers | The cyber lab |
| Analysis | Static only | Static + dynamic (sandbox) |
| Platform | Windows, native | Linux |
| Database | SQLite | PostgreSQL |
| Install | `.exe` wizard | Appliance image or delivered machine |
| Scale | Hundreds of machines | One, or a few |

This split is the central deployment decision. It follows the shape of the
caseload: a large number of officers need a fast yes/no on a suspicious APK, and
a small number of samples genuinely need detonating.

It also means the impersonation checks — which catch most mass-market fraud APKs
on their own, with no sandbox and no internet — reach the people holding the
seized phones.

---

## 2. Hardware requirements

|  | Static only | Full dynamic | Comfortable |
|---|---|---|---|
| CPU | 4 cores | 8 cores **with VT-x / AMD-V** | 8+ cores |
| RAM | 8 GB | 16 GB | 32 GB |
| Disk | 30 GB | 250 GB SSD | 500 GB SSD |
| GPU | none | none | none |

**Hardware virtualisation is the one hard requirement** for the analysis server.
Without VT-x/AMD-V there is no Windows VM and no accelerated Android emulator. It
is frequently disabled by default in the BIOS of office desktops — confirm it
before promising a deployment.

### Memory budget

```
Linux + desktop                    ~3.5 GB
PostgreSQL                         ~0.5 GB
Backend (750 YARA rules in memory) ~1.5 GB
Frontend                           ~0.5 GB
                                   ────────
base                               ~6.0 GB

+ Windows VM detonation             4–8 GB
+ Android emulator                  2–4 GB
```

Base plus **one** sandbox fits in 16 GB. Base plus **both concurrently** does
not. This is not a constraint in practice: only one sample can occupy a sandbox
at a time, so detonations are serialised by design. The hardware limit and the
software design agree.

A useful side effect: VirtualBox and KVM contend for the CPU virtualisation
extensions, and serialising detonations means they are never both active.

32 GB is the threshold at which both sandboxes can run concurrently and two
samples can be analysed at once.

### Disk budget

```
Repo, venv, YARA rules         ~0.5 GB
Android SDK                     3.9 GB
Android system image + AVD     ~12  GB
Windows VM + snapshots         ~60  GB
Samples, pcaps, artifacts       grows continuously
```

Packet captures are the surprise item — a five-minute detonation can produce
hundreds of megabytes, and they accumulate faster than samples do. Plan a
retention policy alongside the evidence-handling procedure.

### No GPU required

The report narrative runs on Ollama's hosted API, so `gemma4:31b` executes on
their hardware. No local GPU is needed.

**Known tension:** air-gapped operation is a project objective, and air-gapped
means no hosted API, therefore no model-written narrative. The system already
degrades correctly — with no key, or `OFFLINE_MODE=true`, the Word report falls
back to the deterministic summary and still builds in full. The offline report
simply reads plainer. Running a local model instead would need roughly 20 GB of
VRAM for a model of this class; a 6–8 GB card limits you to a much smaller model
and noticeably weaker prose.

---

## 3. Current stack

**Backend** — Python 3.13. FastAPI, Uvicorn, pydantic-settings, SQLAlchemy 2.0
(typed, with portable JSON columns so the same models run on PostgreSQL and
SQLite), httpx.

**Analysis** — python-magic (libmagic), yara-python with 750 vendored Neo23x0
rules, pefile for Windows PE, androguard for Android APK. Plus five dependency-free
analysers written for this project: `ioc_extract`, `strings_extract`,
`attack_map`, `android_map`, `apk_signals`.

**Threat intelligence** — VirusTotal, MalwareBazaar, ThreatFox, AbuseIPDB,
urlscan.io. Each isolated so one failure cannot cost the rest of a report.

**Reporting** — python-docx (Word), stix2 (STIX 2.1), stdlib csv. Narrative via
Ollama over plain httpx, no SDK.

**Frontend** — React 18, TypeScript, Vite 6, React Router. Hand-written CSS.
Fonts self-hosted via @fontsource rather than a CDN, because a webfont request
would be the one thing on the page that quietly required the internet.

**Tests** — 233 tests, pytest + respx, `filterwarnings = error`.

The dependency list is deliberately thin. The work is in the project's own
analysis code rather than glue between libraries, which is what allowed the
impersonation detection to be tuned to Indian fraud campaigns specifically.

---

## 4. Packaging the field build

A Windows `.exe` wizard, static analysis only.

Feasible because every static dependency has a Windows wheel: yara-python,
pefile, androguard, python-docx. Postgres is replaced by SQLite, Docker is not
used at all, and the built React app is served as static files by the same
process.

**Wizard flow:** double-click → next → optionally paste API keys, or skip and run
fully offline → desktop shortcut → opens the browser at `localhost`. The officer
never sees a terminal.

**Tooling:** PyInstaller or Nuitka to freeze the Python side; Inno Setup for the
wizard. Expect 300–500 MB, dominated by the YARA rules and analysis libraries.

### Three problems to plan for

**Antivirus will flag the installer.** PyInstaller-packed Python is heavily
flagged — it is the same packaging malware uses — and bundling 750 malware
signatures makes it worse. This needs a code-signing certificate (roughly
$200–500/year) and a reputation-building period with Microsoft. Budget for it
early; it is the most common reason "just ship an exe" stalls.

**Windows Defender will destroy evidence.** The tool stores malware samples on
disk. Defender will quarantine or delete them, silently. The installer must add a
Defender exclusion for the sample storage directory. This requires administrator
rights and is a deliberate security tradeoff — document it, do not hide it.

**Docker Desktop conflicts with the sandbox.** It requires WSL2/Hyper-V, and
Hyper-V takes exclusive control of the CPU virtualisation extensions, breaking
VirtualBox and the Android emulator. This is exactly why the field build must be
native and Docker-free rather than a wizard wrapped around Docker Desktop.

### Keeping the field build possible

The static analysers must stay free of Linux-only assumptions. The only current
obstacle is `python-magic`, which needs libmagic — solvable by bundling the DLL.
Worth checking before any future analyser is added.

---

## 5. Packaging the analysis server

Not an installer. The dynamic side needs VMs, an Android emulator, packet capture
and hardware virtualisation; wrapping that in a wizard fights the platform.

Two options, both standard for forensic tooling:

- **Pre-built appliance image** (OVA or bootable ISO), as REMnux, SIFT Workstation
  and Tsurugi Linux all ship. One file, imported and started, pre-configured.
- **A delivered machine.** Preinstalled and tested before it arrives. Realistic
  for a central lab and the lowest install risk.

---

## 6. Licensing

Everything required is redistributable:

| Component | Licence |
|---|---|
| signature-base (750 YARA rules) | Detection Rule License 1.1 — redistribution with attribution |
| IBM Plex, Archivo | SIL Open Font License |
| androguard | Apache 2.0 |
| python-docx | MIT |
| pefile, yara-python | BSD / Apache |

Nothing blocks distribution of either build.

---

## 7. Cloudflare: assessed and rejected for the core

Considered, and it should not host the analysis engine.

**The blocking reason is evidence handling, not technology.** Samples come from
seized devices in active cases. Sending them to a third party's infrastructure
moves case material out of jurisdiction and inserts a third party into the chain
of custody. The codebase already refuses a much milder version of this:
`virustotal.py` sends only the SHA-256 and never the file, and `urlscan.py` is
search-only, both with comments explaining why. It would also end air-gapped
operation.

**The technical reasons are independent and also decisive.** Workers run V8
isolates — no native C libraries, so no libyara. Python Workers are Pyodide-based
and will not load androguard or lxml. There is no persistent filesystem, request
bodies are far below the 512 MB upload ceiling, and Workers cannot run virtual
machines. Detonation is the opposite shape of compute from edge request handling.

**Where it would genuinely fit,** all touching no case data:

- **Threat-intel feed cache** — the strongest candidate. A scheduled Worker plus
  KV that pulls public feeds (ThreatFox exports, abuse.ch lists) and serves every
  station from one cache, instead of each burning its own provider quota on the
  same indicators. Solves a real ceiling the system already has.
- **YARA rule distribution** — serve signature-base updates from R2 as a
  controlled, versioned mirror.
- **Citizen fraud-reporting portal** — public intake for fraud *links* and phone
  numbers, never files. Fits the mass-market nature of the caseload.
- **Tunnel / Access** — reaching the lab server from stations without opening
  firewall ports. Note that traffic transits Cloudflare's network, which is a
  policy decision for police data rather than a technical one.

---

## 8. Sequencing

Packaging should happen **after** dynamic analysis is complete. Packaging a
moving target means doing it twice.

The one thing to decide now is the field/lab split, because it determines that
the static analysers must remain portable — and that is a constraint on code
being written today.
