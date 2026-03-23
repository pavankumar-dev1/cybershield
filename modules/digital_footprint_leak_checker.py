KNOWN_LEAK_KEYWORDS = ["pastebin", "leak", "dump", "breach", "hacked", "exposed", "darkweb"]

def check_digital_footprint(text):
    found = []
    t = text.lower()
    for k in KNOWN_LEAK_KEYWORDS:
        if k in t:
            found.append(k)

    if found:
        return {
            "status": "HIGH",
            "message": f"Leak keywords detected: {', '.join(found)}",
            "keywords": found
        }
    return {
        "status": "SAFE",
        "message": "No known leak keywords found.",
        "keywords": []
    }
