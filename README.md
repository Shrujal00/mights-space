# 🛡️ Unified Cross-Platform Malware Detection and Behavioral Analysis Suite

> **Problem Statement ID**: `ERH26_PS_04`  
> **Domain**: Cybersecurity & Malware Analysis  
> **Target Deployment**: Cyber Crime Units / Police Departments (Surat Cyber Police)  

---

## 📌 Background & Overview

Police departments increasingly deal with endpoints compromised by sophisticated spyware, Remote Access Trojans (RATs), and malicious Android packages (APKs) used in **light-bill fraud**, **loan-app scams**, **fake RTO/e-Challan schemes**, and financial fraud campaigns.

This suite provides a safe, contained, and air-gapped forensic environment to quickly analyze seized Android APKs and Windows binaries to determine **exactly what data the malware accesses and where it transmits it (Command & Control / Exfiltration destinations)**.

---

## ✨ Key Features

- **📱 Android & 💻 Windows Support**: Analyzes both `.apk` files and Windows PE binaries (`.exe`, `.dll`).
- **🔍 Static Analysis**:
  - Hash calculation (SHA-256, SHA-1, MD5).
  - 734 vendored YARA signatures compiled in memory.
  - APK manifest inspection, dangerous permissions, certificates, and DEX strings.
  - Windows PE section entropy, machine headers, packing indicators, and DLL import tables.
  - Embedded IP, URL, and IOC extraction.
  - Multi-provider threat intelligence enrichment (VirusTotal, ThreatFox, AbuseIPDB, urlscan).
- **🧪 Dynamic / Sandbox Analysis**:
  - **Windows PE**: In-process CPU emulation using `speakeasy-emulator` (no VM or hypervisor needed).
  - **Android APK**: Live instrumentation via `frida` hooks on Android AVD with decoy SMS & contacts seeding.
  - Captures file, registry, SMS inbox, contacts, and network POST requests.
- **⚡ Exfiltration Correlation Engine**:
  - Automatically pairs data-reading actions (e.g., reading SMS inbox) with subsequent network POST transmissions within configurable time windows.
  - Reports exact millisecond delays, bytes sent, and confidence pairings.
- **🛡️ MITRE ATT&CK Mapping**:
  - Maps code capabilities to known MITRE ATT&CK technique IDs (e.g., `T1409`, `T1412`, `T1071`).
- **📄 Evidence-Grade Reports**:
  - Exportable executive Word reports (`.docx`) with plain-language summaries.
  - Exportable IOC feeds in **STIX 2.1 JSON** and **CSV** formats.
- **🔒 Law Enforcement Portal & Management**:
  - Officer authentication screen (Badge Number / Station Unit Code).
  - **Clear/Delete Sample** feature to wipe individual malware samples and database records on demand.
- **🌐 Air-Gapped Operation**:
  - Fully functional offline without external cloud dependencies or CDN calls.

---

## 🏗️ Architecture

```
                       ┌────────────────────────────────────────┐
                       │          React + Vite Frontend         │
                       │        (Law Enforcement Portal)        │
                       └───────────────────┬────────────────────┘
                                           │ HTTP / JSON API
                                           ▼
                       ┌────────────────────────────────────────┐
                       │          FastAPI Backend Service       │
                       └──────┬──────────────────────────┬──────┘
                              │                          │
              ┌───────────────┴──────────────┐   ┌───────┴───────────────┐
              │     Static Triage Engine     │   │ Dynamic Sandbox Engine│
              │  - 734 YARA Rules            │   │  - Speakeasy (Win PE) │
              │  - Androguard (APK)          │   │  - Frida (Android)    │
              │  - Pefile (Windows)          │   └───────────────────────┘
              │  - IOC & Strings Extractor   │
              └───────────────┬──────────────┘
                              │
                              ▼
                       ┌────────────────────────────────────────┐
                       │       SQLite Database & Storage        │
                       │     (Samples, Events, Reports, IOCs)   │
                       └────────────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python**: 3.11+ (Python 3.13 / 3.14 supported)
- **Node.js**: v18+ (Node.js v22/v24 supported) & `npm`

---

### Step 1: Clone the Repository

```bash
git clone https://github.com/Shrujal00/mights-space.git
cd mights-space-master
```

---

### Step 2: Set Up & Run the Backend

Navigate to the `backend/` folder:

```bash
cd backend
```

1. **Create a Python Virtual Environment**:
   - **Windows**:
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\activate
     ```
   - **Linux / macOS**:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

2. **Install Backend Dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install python-magic-bin speakeasy-emulator
   ```

3. **Configure Environment (`backend/.env`)**:
   Create a `.env` file inside `backend/` with the following content:
   ```ini
   OFFLINE_MODE=false
   DATABASE_URL=sqlite:///./malware_analysis.db
   SAMPLE_STORAGE_DIR=storage/samples
   DYNAMIC_ANALYSIS_ENABLED=false
   REPORT_AUTHORITY=SURAT CYBER POLICE INDIA
   ```

4. **Start the FastAPI Server**:
   ```bash
   python -m uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
   ```
   - **Backend API**: [http://localhost:8000](http://localhost:8000)
   - **Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - **Health Endpoint**: [http://localhost:8000/api/health](http://localhost:8000/api/health)

---

### Step 3: Set Up & Run the Frontend

Open a new terminal window and navigate to `frontend/`:

```bash
cd frontend
```

1. **Install Frontend Dependencies**:
   ```bash
   npm install
   ```

2. **Start Vite Development Server**:
   ```bash
   npm run dev
   ```
   - **Frontend UI**: [http://localhost:5173](http://localhost:5173)

---

### Step 4: Run Automated Tests

To run the full backend test suite (386+ tests):

```bash
cd backend
.\.venv\Scripts\pytest.exe
```

---

## 🧪 How to Use the System

1. Open [http://localhost:5173](http://localhost:5173) in your web browser.
2. Log in using your **Badge Number** (or click **"⚡ Quick Demo Login"**).
3. Drag & drop any suspicious **`.apk`** or Windows **`.exe` / `.dll`** sample into the drop zone.
4. View the interactive report:
   - **Verdict Banner**: Malicious / Suspicious / Nothing Known.
   - **Impersonation & Permission Analysis**: SMS/Contacts access, dangerous permissions.
   - **YARA Signatures**: Matched malware rules out of 734 signatures.
   - **What it Can Do**: MITRE ATT&CK technique mapping.
   - **Dynamic Behavior Timeline**: Live API calls, file access, and network exfiltration pairing.
5. Export evidence in **Word (`.docx`)**, **STIX 2.1**, or **CSV** format.
6. Click **Clear analysis** on any sample to permanently delete it from the system.

---

## 📁 Repository Structure

```
mights-space-master/
├── backend/
│   ├── app/
│   │   ├── analysis/       # Static analysers, YARA scanner, MITRE ATT&CK, Exfiltration
│   │   ├── api/            # FastAPI routes (/api/samples, /api/health)
│   │   ├── sandbox/        # Speakeasy (Windows PE) & Frida (Android APK) sandboxes
│   │   ├── config.py       # Pydantic environment configuration
│   │   ├── db.py           # SQLAlchemy database session handling
│   │   ├── main.py         # FastAPI application factory
│   │   └── models.py       # Database schema (Samples, LeafFiles, YaraHits, Detonations)
│   ├── tests/              # Pytest test suite (386 tests)
│   ├── yara_rules/         # 734 vendored YARA rules
│   ├── .env.example        # Environment variable template
│   └── requirements.txt    # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── api/            # API client & TypeScript interfaces
│   │   ├── components/     # React UI components (Timeline, Verdict, DropZone)
│   │   ├── pages/          # Pages (Login, Dashboard, Report)
│   │   └── styles/         # CSS design tokens & stylesheets
│   ├── package.json        # Frontend dependencies
│   └── vite.config.ts      # Vite dev server configuration
├── docs/                   # Deployment and dynamic analysis documentation
├── docker-compose.yml      # Docker compose configuration
├── start.sh                # Shell script to launch full stack
└── README.md               # Project documentation
```

---

## 📜 License & Compliance

Developed for law enforcement cybersecurity and malware triage operations. All vendored rulesets and libraries strictly comply with open-source licenses (Apache 2.0, MIT, Detection Rule License 1.1, SIL Open Font License).
