import ipaddress
from urllib.parse import urlsplit

SUSPICIOUS_TERMS = ["login", "verify", "update", "secure", "free", "win", "prize",
                    "click", "confirm", "account", "suspend", "urgent", "password"]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".cf", ".gq", ".pw"]


def detect_phishing(url):
    score = 0
    flags = []
    text = url.lower()

    # Parse the URL so host-based checks do not inspect paths or query strings.
    try:
        parsed_url = urlsplit(text)
        hostname = (parsed_url.hostname or "").rstrip(".")
    except ValueError:
        parsed_url = None
        hostname = ""

    # Reject malformed, hostless, or unsupported-scheme inputs instead of
    # accidentally treating them as clean URLs.
    if not parsed_url or parsed_url.scheme not in {"http", "https"} or not hostname:
        score += 3
        flags.append("Malformed URL or unsupported scheme")

    # URLs containing embedded credentials can disguise the real destination.
    if parsed_url and parsed_url.username is not None:
        score += 2
        flags.append("URL contains embedded credentials")

    # HTTP (not HTTPS)
    if parsed_url and parsed_url.scheme == "http":
        score += 2
        flags.append("Uses HTTP (not secure)")

    # Suspicious keywords
    matched = [term for term in SUSPICIOUS_TERMS if term in text]
    score += len(matched)
    if matched:
        flags.append(f"Suspicious words: {', '.join(matched)}")

    # IP address URL (supports valid IPv4 and IPv6 literals).
    is_ip_address = False
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            pass

    if is_ip_address:
        score += 3
        flags.append("URL uses IP address instead of domain")

    # Suspicious TLD: inspect only the actual hostname suffix.
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 2
            flags.append(f"Suspicious domain extension: {tld}")

    # Too many subdomains (exclude IP literals).
    if hostname and not is_ip_address and len(hostname.split(".")) > 4:
        score += 1
        flags.append("Too many subdomains")

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
