"""Human-readable descriptions for Android permissions.

Descriptions are written in plain English for a non-developer reader. Each
entry is (description, risk_tier) where risk_tier is one of:

    "normal"   - Low risk, typical app use
    "elevated" - Privacy-sensitive or broad device access
    "high"     - Frequently abused by malware / phishing apps

The risk tier is *advisory*. A "high" permission is not automatically bad,
but on a phishing triage it deserves human review.
"""

from __future__ import annotations

# (description, risk_tier)
PERMISSIONS: dict[str, tuple[str, str]] = {
    # --- Network ---
    "android.permission.INTERNET": (
        "Open network sockets (access the internet).",
        "normal",
    ),
    "android.permission.ACCESS_NETWORK_STATE": (
        "Check whether the device is online and on what kind of network.",
        "normal",
    ),
    "android.permission.ACCESS_WIFI_STATE": (
        "Check the current Wi-Fi connection state and nearby networks.",
        "normal",
    ),
    "android.permission.CHANGE_WIFI_STATE": (
        "Turn Wi-Fi on/off and join networks.",
        "elevated",
    ),
    "android.permission.CHANGE_WIFI_MULTICAST_STATE": (
        "Receive multicast Wi-Fi packets (e.g. for mDNS / device discovery).",
        "normal",
    ),
    "android.permission.CHANGE_NETWORK_STATE": (
        "Change network connectivity state.",
        "elevated",
    ),
    "android.permission.NEARBY_WIFI_DEVICES": (
        "Scan and connect to nearby Wi-Fi devices without location access.",
        "elevated",
    ),

    # --- Storage / files ---
    "android.permission.READ_EXTERNAL_STORAGE": (
        "Read files from shared/external storage.",
        "elevated",
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        "Write files to shared/external storage.",
        "elevated",
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (
        "Broad read/write access to all shared storage. Google restricts this.",
        "high",
    ),
    "android.permission.READ_MEDIA_IMAGES": (
        "Read image files from the device.",
        "elevated",
    ),
    "android.permission.READ_MEDIA_VIDEO": (
        "Read video files from the device.",
        "elevated",
    ),
    "android.permission.READ_MEDIA_AUDIO": (
        "Read audio files from the device.",
        "elevated",
    ),

    # --- Location ---
    "android.permission.ACCESS_FINE_LOCATION": (
        "Get the device's precise GPS location.",
        "elevated",
    ),
    "android.permission.ACCESS_COARSE_LOCATION": (
        "Get the device's approximate (cell/Wi-Fi) location.",
        "elevated",
    ),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (
        "Get location even while the app is in the background.",
        "high",
    ),

    # --- Identity / accounts ---
    "android.permission.GET_ACCOUNTS": (
        "See which accounts are configured on the device (Google, email, etc.).",
        "elevated",
    ),
    "android.permission.AUTHENTICATE_ACCOUNTS": (
        "Act as an account authenticator to the Android AccountManager.",
        "elevated",
    ),
    "android.permission.MANAGE_ACCOUNTS": (
        "Create, update, and remove accounts in the AccountManager.",
        "elevated",
    ),
    "android.permission.USE_CREDENTIALS": (
        "Request auth tokens from the AccountManager for existing accounts.",
        "elevated",
    ),
    "android.permission.READ_PROFILE": (
        "Read the user's personal profile info.",
        "elevated",
    ),
    "android.permission.READ_CONTACTS": (
        "Read the user's contact list. Commonly abused for contact harvesting.",
        "high",
    ),
    "android.permission.WRITE_CONTACTS": (
        "Modify the user's contact list.",
        "high",
    ),

    # --- Telephony / SMS / calls ---
    "android.permission.READ_PHONE_STATE": (
        "Read phone number, carrier, IMEI, and call state.",
        "high",
    ),
    "android.permission.READ_PHONE_NUMBERS": (
        "Read the device's own phone number(s).",
        "elevated",
    ),
    "android.permission.CALL_PHONE": (
        "Initiate phone calls without user confirmation.",
        "high",
    ),
    "android.permission.READ_CALL_LOG": (
        "Read the device call history. Google restricts this permission.",
        "high",
    ),
    "android.permission.WRITE_CALL_LOG": (
        "Modify the device call history.",
        "high",
    ),
    "android.permission.PROCESS_OUTGOING_CALLS": (
        "Intercept or redirect outbound calls.",
        "high",
    ),
    "android.permission.ANSWER_PHONE_CALLS": (
        "Answer incoming phone calls programmatically.",
        "high",
    ),
    "android.permission.READ_SMS": (
        "Read SMS messages. Classic banking-trojan permission (2FA theft).",
        "high",
    ),
    "android.permission.RECEIVE_SMS": (
        "Intercept incoming SMS. Classic banking-trojan permission (2FA theft).",
        "high",
    ),
    "android.permission.SEND_SMS": (
        "Send SMS messages (potentially premium-rate).",
        "high",
    ),
    "android.permission.WRITE_SMS": (
        "Modify SMS messages stored on the device.",
        "high",
    ),
    "android.permission.RECEIVE_MMS": (
        "Intercept incoming MMS messages.",
        "high",
    ),
    "android.permission.RECEIVE_WAP_PUSH": (
        "Intercept WAP push messages (carrier-level messages).",
        "high",
    ),

    # --- Hardware ---
    "android.permission.CAMERA": (
        "Access the camera for photos and video.",
        "elevated",
    ),
    "android.permission.RECORD_AUDIO": (
        "Record from the microphone.",
        "elevated",
    ),
    "android.permission.BODY_SENSORS": (
        "Read body sensor data (e.g. heart rate).",
        "elevated",
    ),
    "android.permission.USE_FINGERPRINT": (
        "Use the fingerprint sensor (deprecated; see USE_BIOMETRIC).",
        "elevated",
    ),
    "android.permission.USE_BIOMETRIC": (
        "Authenticate the user using biometrics.",
        "elevated",
    ),
    "android.permission.VIBRATE": (
        "Control the device vibrator.",
        "normal",
    ),
    "android.permission.FLASHLIGHT": (
        "Use the camera flashlight.",
        "normal",
    ),
    "android.permission.BLUETOOTH": (
        "Pair with and communicate over Bluetooth.",
        "normal",
    ),
    "android.permission.BLUETOOTH_ADMIN": (
        "Discover and configure Bluetooth devices.",
        "elevated",
    ),
    "android.permission.BLUETOOTH_CONNECT": (
        "Connect to previously paired Bluetooth devices (Android 12+).",
        "elevated",
    ),
    "android.permission.BLUETOOTH_SCAN": (
        "Scan for nearby Bluetooth devices (Android 12+).",
        "elevated",
    ),
    "android.permission.BLUETOOTH_ADVERTISE": (
        "Advertise as a Bluetooth peripheral to nearby devices.",
        "elevated",
    ),
    "android.permission.NFC": (
        "Perform near-field communication (e.g. tap-to-pay, badge reads).",
        "elevated",
    ),

    # --- Background / lifecycle ---
    "android.permission.WAKE_LOCK": (
        "Keep the CPU awake so the app can run while the screen is off.",
        "normal",
    ),
    "android.permission.FOREGROUND_SERVICE": (
        "Run a foreground service with a persistent notification.",
        "normal",
    ),
    "android.permission.FOREGROUND_SERVICE_LOCATION": (
        "Run a foreground service that uses location.",
        "elevated",
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": (
        "Automatically start when the device finishes booting (persistence).",
        "elevated",
    ),
    "android.permission.SCHEDULE_EXACT_ALARM": (
        "Schedule alarms that fire at an exact time.",
        "normal",
    ),
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": (
        "Ask to be exempted from battery optimizations (stay alive in background).",
        "elevated",
    ),
    "android.permission.DISABLE_KEYGUARD": (
        "Dismiss the keyguard (lock screen) if it isn't secure.",
        "elevated",
    ),
    "android.permission.REORDER_TASKS": (
        "Move activities between tasks. Can be abused for UI spoofing.",
        "elevated",
    ),

    # --- Sync adapters ---
    "android.permission.READ_SYNC_SETTINGS": (
        "Read sync settings for accounts.",
        "normal",
    ),
    "android.permission.WRITE_SYNC_SETTINGS": (
        "Modify sync settings for accounts.",
        "normal",
    ),
    "android.permission.READ_SYNC_STATS": (
        "Read sync statistics for accounts.",
        "normal",
    ),

    # --- Calendar ---
    "android.permission.READ_CALENDAR": (
        "Read the user's calendar events.",
        "elevated",
    ),
    "android.permission.WRITE_CALENDAR": (
        "Add, modify, or delete calendar events.",
        "elevated",
    ),

    # --- Packages / installer ---
    "android.permission.QUERY_ALL_PACKAGES": (
        "See the full list of every app installed on the device.",
        "elevated",
    ),
    "android.permission.INSTALL_PACKAGES": (
        "Install other APK files. Privileged / system-only on modern Android.",
        "high",
    ),
    "android.permission.DELETE_PACKAGES": (
        "Delete other installed apps. Privileged / system-only.",
        "high",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "Prompt the user to install another APK. Classic dropper / alt-store pattern.",
        "high",
    ),
    "android.permission.REQUEST_DELETE_PACKAGES": (
        "Prompt the user to uninstall another app.",
        "high",
    ),
    "android.permission.CLEAR_APP_CACHE": (
        "Clear cached data of other apps.",
        "elevated",
    ),
    "android.permission.GET_PACKAGE_SIZE": (
        "Query storage usage of installed apps.",
        "normal",
    ),

    # --- Sensitive UI / control ---
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "Draw windows on top of other apps. Used for legitimate overlays and for "
        "overlay phishing attacks. High risk on a suspicious APK.",
        "high",
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        "Run as an accessibility service (can read any screen and inject input). "
        "Extremely powerful; the #1 abuse vector for Android banking trojans.",
        "high",
    ),
    "android.permission.BIND_DEVICE_ADMIN": (
        "Become a device administrator. Used for MDM; also for persistence "
        "and anti-uninstall by malware.",
        "high",
    ),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": (
        "Read every notification on the device, including 2FA codes.",
        "high",
    ),
    "android.permission.ACCESS_NOTIFICATION_POLICY": (
        "Change Do Not Disturb settings.",
        "elevated",
    ),
    "android.permission.BIND_INPUT_METHOD": (
        "Run as an input method (keylogging risk).",
        "high",
    ),
    "android.permission.WRITE_SETTINGS": (
        "Modify system settings.",
        "elevated",
    ),
    "android.permission.WRITE_SECURE_SETTINGS": (
        "Modify secure system settings. Privileged / system-only.",
        "high",
    ),
    "android.permission.PACKAGE_USAGE_STATS": (
        "Read which apps the user has been using and for how long.",
        "high",
    ),
    "android.permission.DUMP": (
        "Dump state from system services. Privileged / system-only.",
        "high",
    ),
    "android.permission.READ_LOGS": (
        "Read the system logs (may contain other apps' data).",
        "high",
    ),
    "android.permission.CAPTURE_VIDEO_OUTPUT": (
        "Capture video output from the device. Privileged.",
        "high",
    ),
    "android.permission.CAPTURE_AUDIO_OUTPUT": (
        "Capture system audio output. Privileged.",
        "high",
    ),

    # --- Google Play / vendor ---
    "com.google.android.c2dm.permission.RECEIVE": (
        "Receive Google Cloud Messaging / FCM push notifications.",
        "normal",
    ),
    "com.google.android.c2dm.permission.SEND": (
        "Send GCM/FCM messages (normally system-only).",
        "elevated",
    ),
    "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE": (
        "Read the install-referrer string from Google Play (attribution).",
        "normal",
    ),
    "com.google.android.gms.permission.AD_ID": (
        "Read the Google advertising ID.",
        "normal",
    ),
    "com.google.android.gms.auth.api.signin.permission.REVOCATION_NOTIFICATION": (
        "Receive Google Sign-In revocation notifications.",
        "normal",
    ),
    "com.android.launcher.permission.INSTALL_SHORTCUT": (
        "Add a homescreen shortcut. Can be abused to plant fake-brand icons.",
        "elevated",
    ),
    "com.android.launcher.permission.UNINSTALL_SHORTCUT": (
        "Remove a homescreen shortcut.",
        "normal",
    ),

    # --- Job / work ---
    "android.permission.BIND_JOB_SERVICE": (
        "Allow the system to bind to a JobService for scheduled work.",
        "normal",
    ),
}


def describe(permission: str) -> tuple[str, str]:
    """Look up a permission. Returns (description, risk_tier).

    For unknown permissions, returns a best-effort label and 'unknown' tier.
    """
    if permission in PERMISSIONS:
        return PERMISSIONS[permission]
    # Best-effort: custom app permissions
    if ".permission." in permission:
        owner = permission.split(".permission.", 1)[0]
        return (f"Custom permission defined by {owner}.", "unknown")
    return ("Unknown permission (no description available).", "unknown")
