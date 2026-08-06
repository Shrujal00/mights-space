"""Maps Windows imports to MITRE ATT&CK techniques.

Everything here is derived from the import table alone. That shows what a sample
is *capable* of, not what it was seen doing — nothing is executed anywhere in
this project. Every technique therefore carries `basis="static-import"` so the
report can say "can do X" rather than "did X", which matters when the output is
read by someone who may treat it as evidence.
"""

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    plain_language: str
    evidence: tuple[str, ...]
    basis: str = "static-import"


# technique id -> (ATT&CK name, plain-language description, triggering imports)
TECHNIQUE_SIGNATURES: dict[str, tuple[str, str, frozenset[str]]] = {
    "T1056.001": (
        "Input Capture: Keylogging",
        "Can record everything typed on the keyboard, including passwords and "
        "one-time codes.",
        frozenset(
            {
                "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
                "GetKeyboardState", "RegisterRawInputDevices", "AttachThreadInput",
            }
        ),
    ),
    "T1055": (
        "Process Injection",
        "Can hide its own code inside another running program to avoid being "
        "noticed.",
        frozenset(
            {
                "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                "NtWriteVirtualMemory", "QueueUserAPC", "SetThreadContext",
                "RtlCreateUserThread", "NtMapViewOfSection",
            }
        ),
    ),
    "T1113": (
        "Screen Capture",
        "Can take pictures of whatever is on the screen.",
        frozenset(
            {
                "BitBlt", "CreateCompatibleBitmap", "CreateCompatibleDC",
                "PrintWindow", "GetDesktopWindow", "GdipSaveImageToFile",
            }
        ),
    ),
    "T1071": (
        "Application Layer Protocol",
        "Can send and receive data over the internet.",
        frozenset(
            {
                "InternetOpenUrl", "InternetConnect", "InternetReadFile",
                "HttpOpenRequest", "HttpSendRequest", "WinHttpConnect",
                "WinHttpOpenRequest", "WinHttpSendRequest", "WSAConnect",
            }
        ),
    ),
    "T1105": (
        "Ingress Tool Transfer",
        "Can download further files onto the computer.",
        frozenset({"URLDownloadToFile", "URLDownloadToCacheFile"}),
    ),
    "T1547.001": (
        "Boot or Logon Autostart Execution: Registry Run Keys",
        "Can change Windows settings so it starts again automatically every time "
        "the computer is switched on.",
        frozenset({"RegSetValueEx", "RegCreateKeyEx"}),
    ),
    "T1057": (
        "Process Discovery",
        "Can list the other programs running on the computer, often to spot "
        "antivirus software.",
        frozenset(
            {"CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses"}
        ),
    ),
    "T1082": (
        "System Information Discovery",
        "Can collect details about the computer, such as its name and Windows "
        "version.",
        frozenset({"GetSystemInfo", "GetComputerName", "GetVersionEx", "GetNativeSystemInfo"}),
    ),
    "T1123": (
        "Audio Capture",
        "Can record sound from the microphone.",
        frozenset({"waveInOpen", "waveInStart"}),
    ),
    "T1486": (
        "Data Encrypted for Impact",
        "Can encrypt files, which is how ransomware locks a victim out of their "
        "own data.",
        frozenset({"CryptEncrypt", "CryptDeriveKey", "CryptGenKey"}),
    ),
}


def normalize_import(name: str) -> str:
    """Drop the trailing ANSI/wide suffix Windows appends to most string APIs."""
    if len(name) > 2 and name[-1] in ("A", "W"):
        return name[:-1]
    return name


def map_imports_to_techniques(imports: Iterable[str]) -> list[Technique]:
    """Techniques implied by an import table, in order of first match."""
    evidence: dict[str, list[str]] = {}

    for raw_name in imports:
        normalized = normalize_import(raw_name)
        for technique_id, (_, _, triggers) in TECHNIQUE_SIGNATURES.items():
            if normalized in triggers:
                evidence.setdefault(technique_id, []).append(raw_name)

    techniques = []
    for technique_id, triggering_imports in evidence.items():
        name, plain_language, _ = TECHNIQUE_SIGNATURES[technique_id]
        techniques.append(
            Technique(
                technique_id=technique_id,
                name=name,
                plain_language=plain_language,
                evidence=tuple(triggering_imports),
            )
        )
    return techniques
