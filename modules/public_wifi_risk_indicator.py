ENCRYPTION_SCORES = {
    "OPEN": 0,
    "WEP":  1,
    "WPA":  2,
    "WPA2": 3,
    "WPA3": 4
}

def wifi_risk(encryption, is_public):
    enc = encryption.upper().strip()
    enc_score = ENCRYPTION_SCORES.get(enc, 2)
    flags = []

    if is_public:
        flags.append("Connected to a public network")

    if enc == "OPEN":
        flags.append("No encryption — traffic is fully exposed")
    elif enc == "WEP":
        flags.append("WEP encryption is broken and easily cracked")
    elif enc == "WPA":
        flags.append("WPA has known vulnerabilities")

    # Determine risk
    if enc == "OPEN" and is_public:
        status = "HIGH"
    elif enc in ["OPEN", "WEP"] or (is_public and enc == "WPA"):
        status = "MEDIUM"
    else:
        status = "SAFE"

    tips = []
    if status != "SAFE":
        tips.append("Use a VPN on public or unsecured networks")
        tips.append("Avoid accessing banking or sensitive accounts")
        if enc in ["OPEN", "WEP", "WPA"]:
            tips.append("Switch to a WPA2/WPA3 network if possible")

    return {
        "status": status,
        "encryption": enc,
        "is_public": is_public,
        "flags": flags,
        "tips": tips,
        "message": f"WiFi Risk: {status} ({enc}, {'Public' if is_public else 'Private'})"
    }
