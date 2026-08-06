"""Maps Android permissions and API references to MITRE ATT&CK Mobile techniques.

The Windows equivalent (`attack_map.py`) reads an import table. Android gives two
weaker but complementary signals: the permissions an app *requests* in its
manifest, and the framework classes its code *references* in the DEX. Neither
proves the app does the thing — a permission may go unused, and a referenced
class may sit in dead code or a bundled advertising SDK.

So both are treated as capability, never behaviour, and every technique keeps
`basis="static-manifest"`. A permission alone is weaker evidence than a
permission backed by the matching API reference, and the report says which of
the two it found.

The technique set is weighted towards the fraud this tool exists for: loan-app
extortion (SMS/OTP theft, contact harvesting for blackmail) and fake e-Challan
or RTO phishing.
"""

from typing import Iterable

from .attack_map import Technique

PREFIX = "android.permission."


def _perms(*names: str) -> frozenset[str]:
    return frozenset(PREFIX + name for name in names)


# technique id -> (name, plain language, triggering permissions, DEX markers)
ANDROID_SIGNATURES: dict[str, tuple[str, str, frozenset[str], frozenset[str]]] = {
    "T1636.004": (
        "Protected User Data: SMS Messages",
        "Can read the text messages on the phone, including the one-time codes "
        "banks send to confirm payments.",
        _perms("READ_SMS", "RECEIVE_SMS"),
        frozenset({"Landroid/telephony/SmsMessage", "content://sms", "Telephony$Sms"}),
    ),
    "T1582": (
        "SMS Control",
        "Can send text messages from the phone without the owner being asked, "
        "including to premium-rate numbers.",
        _perms("SEND_SMS"),
        frozenset({"sendTextMessage", "sendMultipartTextMessage", "SmsManager"}),
    ),
    "T1636.003": (
        "Protected User Data: Contact List",
        "Can read the entire contact list. In loan-app extortion this is what "
        "gets used to threaten the victim's family and colleagues.",
        _perms("READ_CONTACTS", "GET_ACCOUNTS"),
        frozenset({"ContactsContract", "content://contacts", "content://com.android.contacts"}),
    ),
    "T1636.002": (
        "Protected User Data: Call Log",
        "Can read the record of who the phone has called and who has called it.",
        _perms("READ_CALL_LOG", "PROCESS_OUTGOING_CALLS"),
        frozenset({"CallLog", "content://call_log"}),
    ),
    "T1430": (
        "Location Tracking",
        "Can find where the phone is, precisely enough to identify a home address.",
        _perms("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"),
        frozenset({"LocationManager", "getLastKnownLocation", "FusedLocationProvider"}),
    ),
    "T1429": (
        "Audio Capture",
        "Can switch on the microphone and record sound.",
        _perms("RECORD_AUDIO"),
        frozenset({"MediaRecorder", "AudioRecord"}),
    ),
    "T1512": (
        "Video Capture",
        "Can switch on the camera and take pictures or video.",
        _perms("CAMERA"),
        frozenset({"Landroid/hardware/Camera", "CameraManager", "camera2"}),
    ),
    "T1513": (
        "Screen Capture",
        "Can record whatever is shown on the screen, including banking apps in use.",
        frozenset(),
        frozenset({"MediaProjection", "createScreenCaptureIntent"}),
    ),
    "T1517": (
        "Access Notifications",
        "Can read every notification the phone shows, which is another way to "
        "capture one-time codes without opening the messaging app.",
        _perms("BIND_NOTIFICATION_LISTENER_SERVICE", "ACCESS_NOTIFICATION_POLICY"),
        frozenset({"NotificationListenerService"}),
    ),
    "T1516": (
        "Input Injection",
        "Can read the contents of other apps on screen and tap buttons by itself. "
        "This is normally an accessibility feature for disabled users, and is "
        "commonly misused to operate banking apps on the victim's behalf.",
        _perms("BIND_ACCESSIBILITY_SERVICE"),
        frozenset({"AccessibilityService", "AccessibilityNodeInfo"}),
    ),
    "T1626.001": (
        "Abuse Elevation Control: Device Administrator",
        "Can make itself a device administrator, which makes the app much harder "
        "to remove and can let it lock or wipe the phone.",
        _perms("BIND_DEVICE_ADMIN"),
        frozenset({"DevicePolicyManager", "DeviceAdminReceiver"}),
    ),
    "T1409": (
        "Stored Application Data",
        "Can read files stored on the phone, such as photographs and documents.",
        _perms("READ_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES"),
        frozenset({"getExternalStorageDirectory", "MediaStore"}),
    ),
    "T1437": (
        "Application Layer Protocol",
        "Can send and receive data over the internet.",
        _perms("INTERNET"),
        frozenset({"HttpURLConnection", "okhttp3", "Retrofit", "Lorg/apache/http"}),
    ),
    "T1407": (
        "Download New Code at Runtime",
        "Can fetch and run additional code after installation, so what it does can "
        "be changed later without updating the app.",
        _perms("REQUEST_INSTALL_PACKAGES"),
        frozenset({"DexClassLoader", "PathClassLoader", "loadDex"}),
    ),
    "T1398": (
        "Boot or Logon Initialization Scripts",
        "Can start itself automatically every time the phone is switched on.",
        _perms("RECEIVE_BOOT_COMPLETED"),
        frozenset({"BOOT_COMPLETED"}),
    ),
    "T1541": (
        "Foreground Persistence",
        "Can keep itself running in the background so it is not easily stopped.",
        _perms("FOREGROUND_SERVICE", "WAKE_LOCK", "SYSTEM_ALERT_WINDOW"),
        frozenset({"startForeground", "TYPE_APPLICATION_OVERLAY"}),
    ),
    "T1426": (
        "System Information Discovery",
        "Can collect identifying details about the phone, such as its serial "
        "number, network operator and SIM details.",
        _perms("READ_PHONE_STATE", "READ_PRIVILEGED_PHONE_STATE"),
        frozenset({"TelephonyManager", "getDeviceId", "getSubscriberId", "getSimSerialNumber"}),
    ),
    "T1418": (
        "Software Discovery",
        "Can list the other apps installed on the phone, often to look for "
        "banking apps or security software.",
        _perms("QUERY_ALL_PACKAGES"),
        frozenset({"getInstalledPackages", "getInstalledApplications"}),
    ),
    "T1406": (
        "Obfuscated Files or Information",
        "Contains code that has been deliberately scrambled or encrypted to make "
        "it harder to examine.",
        frozenset(),
        frozenset({"javax/crypto/Cipher", "AESCrypt", "Base64.decode"}),
    ),
}

# Permissions Android itself classes as dangerous — those that gate personal data
# or hardware. Used to summarise risk without needing the full technique map.
DANGEROUS_PERMISSIONS = frozenset(
    _perms(
        "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
        "READ_CALL_LOG", "WRITE_CALL_LOG", "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO",
        "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "MANAGE_EXTERNAL_STORAGE", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
        "CALL_PHONE", "GET_ACCOUNTS", "READ_CALENDAR", "WRITE_CALENDAR",
        "BODY_SENSORS", "ACTIVITY_RECOGNITION", "READ_MEDIA_IMAGES",
        "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
    )
)

# Permissions that are not "dangerous" in Android's own classification but which
# are the defining tell of the fraud families this tool is aimed at.
HIGH_ABUSE_PERMISSIONS = frozenset(
    _perms(
        "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW",
        "REQUEST_INSTALL_PACKAGES", "BIND_NOTIFICATION_LISTENER_SERVICE",
    )
)


def map_android_to_techniques(
    permissions: Iterable[str],
    api_markers: Iterable[str] = (),
) -> list[Technique]:
    """Techniques implied by a manifest and the app's code references.

    A technique is reported when either signal fires. The evidence records which,
    so a reader can tell a declared-but-unused permission from one the code
    actually reaches for.
    """
    requested = {p for p in permissions}
    markers = list(api_markers)

    techniques: list[Technique] = []
    for technique_id, (name, plain, perms, dex_markers) in ANDROID_SIGNATURES.items():
        evidence: list[str] = []

        for permission in sorted(requested & perms):
            evidence.append(permission.replace(PREFIX, ""))

        for marker in dex_markers:
            if any(marker in candidate for candidate in markers):
                evidence.append(f"code reference: {marker}")

        if evidence:
            techniques.append(
                Technique(
                    technique_id=technique_id,
                    name=name,
                    plain_language=plain,
                    evidence=tuple(dict.fromkeys(evidence)),
                    basis="static-manifest",
                )
            )
    return techniques


def dangerous(permissions: Iterable[str]) -> list[str]:
    return sorted(p for p in permissions if p in DANGEROUS_PERMISSIONS)


def high_abuse(permissions: Iterable[str]) -> list[str]:
    return sorted(p for p in permissions if p in HIGH_ABUSE_PERMISSIONS)
