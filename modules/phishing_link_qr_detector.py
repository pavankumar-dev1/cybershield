import re

SUSPICIOUS_TERMS = ["login", "verify", "update", "secure", "free", "win", "prize",
                    "click", "confirm", "account", "suspend", "urgent", "password"]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".cf", ".gq", ".pw"]

def detect_phishing(url):
    score = 0
    flags = []
    text = url.lower()

    # HTTP (not HTTPS)
    if text.startswith("http://"):
        score += 2
        flags.append("Uses HTTP (not secure)")

    # Suspicious keywords
    matched = [t for t in SUSPICIOUS_TERMS if t in text]
    score += len(matched)
    if matched:
        flags.append(f"Suspicious words: {', '.join(matched)}")

    # IP address URL
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text):
        score += 3
        flags.append("URL uses IP address instead of domain")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if tld in text:
            score += 2
            flags.append(f"Suspicious domain extension: {tld}")

    # Too many subdomains
    try:
        domain_part = re.sub(r"https?://", "", text).split("/")[0]
        if domain_part.count(".") > 3:
            score += 1
            flags.append("Too many subdomains")
    except:
        pass

    if score >= 4:
        status = "HIGH"
    elif score >= 2:
        status = "MEDIUM"
    else:
        status = "SAFE"

    return {
        "status": status,
        "score": score,
        "flags": flags,
        "message": f"Phishing risk: {status} ({score} indicators found)"
    }
