DANGEROUS_PERMISSIONS = {
    "READ_SMS":              "Can read your private SMS messages",
    "SEND_SMS":              "Can send SMS on your behalf (charges may apply)",
    "RECORD_AUDIO":          "Can silently record microphone audio",
    "READ_CONTACTS":         "Can access all your contacts",
    "ACCESS_FINE_LOCATION":  "Can track your exact GPS location",
    "READ_CALL_LOG":         "Can read your call history",
    "PROCESS_OUTGOING_CALLS":"Can intercept or redirect your calls",
    "CAMERA":                "Can silently take photos/videos",
    "READ_EXTERNAL_STORAGE": "Can read all files on your device",
    "WRITE_EXTERNAL_STORAGE":"Can modify or delete your files",
    "GET_ACCOUNTS":          "Can access all accounts on your device",
    "USE_BIOMETRIC":         "Can access biometric data"
}

def analyze_permissions(permissions):
    risky = []
    safe = []

    for p in permissions:
        p_upper = p.strip().upper()
        if p_upper in DANGEROUS_PERMISSIONS:
            risky.append({
                "permission": p_upper,
                "reason": DANGEROUS_PERMISSIONS[p_upper]
            })
        elif p_upper:
            safe.append(p_upper)

    if len(risky) >= 3:
        status = "HIGH"
    elif len(risky) >= 1:
        status = "MEDIUM"
    else:
        status = "SAFE"

    return {
        "status": status,
        "risky": risky,
        "safe": safe,
        "message": f"{len(risky)} dangerous permission(s) found" if risky else "No dangerous permissions detected"
    }
