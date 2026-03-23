import re

def analyze_password(password):
    score = 0
    tips = []

    if len(password) >= 8:
        score += 1
    else:
        tips.append("Use at least 8 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        tips.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        tips.append("Add lowercase letters")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        tips.append("Add numbers")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        tips.append("Add special characters (!@#$...)")

    if score <= 2:
        status = "WEAK"
    elif score <= 4:
        status = "MEDIUM"
    else:
        status = "STRONG"

    return {
        "status": status,
        "score": score,
        "max_score": 5,
        "tips": tips,
        "message": f"Password is {status.capitalize()} ({score}/5)"
    }
