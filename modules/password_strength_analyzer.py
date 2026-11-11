import unicodedata


def analyze_password(password):
    score = 0
    tips = []

    if len(password) >= 12:
        score += 1
    else:
        tips.append("Use at least 12 characters")

    if any(char.isupper() for char in password):
        score += 1
    else:
        tips.append("Add uppercase letters")

    if any(char.islower() for char in password):
        score += 1
    else:
        tips.append("Add lowercase letters")

    if any(char.isdecimal() for char in password):
        score += 1
    else:
        tips.append("Add numbers")

    if any(unicodedata.category(char)[0] in {"P", "S"} for char in password):
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
