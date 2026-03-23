def build_dashboard(results):
    STATUS_WEIGHT = {"HIGH": 2, "MEDIUM": 1, "SAFE": 0}

    total_score = 0
    breakdown = {}

    for module, result in results.items():
        status = result.get("status", "SAFE")
        weight = STATUS_WEIGHT.get(status, 0)
        total_score += weight
        breakdown[module] = {
            "status": status,
            "message": result.get("message", "")
        }

    max_score = len(results) * 2

    if total_score == 0:
        overall = "SAFE"
        summary = "No threats detected. You're secure!"
    elif total_score <= max_score * 0.4:
        overall = "LOW"
        summary = "Minor risks detected. Review flagged modules."
    elif total_score <= max_score * 0.7:
        overall = "MEDIUM"
        summary = "Moderate risk. Take action on flagged areas."
    else:
        overall = "HIGH"
        summary = "High risk detected! Immediate action recommended."

    return {
        "overall": overall,
        "summary": summary,
        "score": total_score,
        "max_score": max_score,
        "breakdown": breakdown
    }
