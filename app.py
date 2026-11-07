from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from digital_footprint_leak_checker import check_digital_footprint
from password_strength_analyzer import analyze_password
from phishing_link_qr_detector import detect_phishing
from rogue_app_permission_analyzer import analyze_permissions
from public_wifi_risk_indicator import wifi_risk
from cyber_risk_dashboard import build_dashboard

app = Flask(__name__)
CORS(app)


def _get_json_payload():
    """Return a JSON object, or None when the request body is invalid."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _invalid_json_response():
    return jsonify({"error": "Request body must be a valid JSON object"}), 400


def _validate_string_fields(data, *fields):
    """Reject supplied fields that should contain text, not other JSON types."""
    for field in fields:
        if field in data and not isinstance(data[field], str):
            return jsonify({"error": f"Field '{field}' must be a string"}), 400
    return None


def _validate_permissions_field(data):
    """Accept comma-separated text or a list containing only strings."""
    if "permissions" not in data:
        return None

    permissions = data["permissions"]
    if isinstance(permissions, str):
        return None
    if isinstance(permissions, list) and all(
        isinstance(permission, str) for permission in permissions
    ):
        return None

    return jsonify({
        "error": "Field 'permissions' must be a string or a list of strings"
    }), 400


def _validate_is_public_field(data):
    """Require a JSON boolean for the public-network flag."""
    if "is_public" in data and not isinstance(data["is_public"], bool):
        return jsonify({"error": "Field 'is_public' must be a boolean"}), 400
    return None


# ── Serve frontend ────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/footprint", methods=["POST"])
def api_footprint():
    data = _get_json_payload()
    if data is None:
        return _invalid_json_response()
    validation_error = _validate_string_fields(data, "text")
    if validation_error:
        return validation_error
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "No text provided"}), 400
    return jsonify(check_digital_footprint(text))


@app.route("/api/password", methods=["POST"])
def api_password():
    data = _get_json_payload()
    if data is None:
        return _invalid_json_response()
    validation_error = _validate_string_fields(data, "password")
    if validation_error:
        return validation_error
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    return jsonify(analyze_password(password))


@app.route("/api/phishing", methods=["POST"])
def api_phishing():
    data = _get_json_payload()
    if data is None:
        return _invalid_json_response()
    validation_error = _validate_string_fields(data, "url")
    if validation_error:
        return validation_error
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(detect_phishing(url))


@app.route("/api/permissions", methods=["POST"])
def api_permissions():
    data = _get_json_payload()
    if data is None:
        return _invalid_json_response()
    validation_error = _validate_permissions_field(data)
    if validation_error:
        return validation_error
    perms = data.get("permissions", [])
    if isinstance(perms, str):
        perms = [p.strip() for p in perms.split(",")]
    return jsonify(analyze_permissions(perms))


@app.route("/api/wifi", methods=["POST"])
def api_wifi():
    data = _get_json_payload()
    if data is None:
        return _invalid_json_response()
    validation_error = _validate_string_fields(data, "encryption")
    if validation_error:
        return validation_error
    validation_error = _validate_is_public_field(data)
    if validation_error:
        return validation_error
    encryption = data.get("encryption", "WPA2")
    is_public = data.get("is_public", False)
    return jsonify(wifi_risk(encryption, is_public))


@app.route("/api/scan-all", methods=["POST"])
def api_scan_all():
    data = _get_json_payload()
    if data is None:
        return _invalid_json_response()

    validation_error = _validate_string_fields(
        data, "text", "password", "url", "encryption"
    )
    if validation_error:
        return validation_error
    validation_error = _validate_permissions_field(data)
    if validation_error:
        return validation_error
    validation_error = _validate_is_public_field(data)
    if validation_error:
        return validation_error

    results = {}

    # Footprint
    text = data.get("text", "")
    results["Digital Footprint"] = check_digital_footprint(text)

    # Password
    password = data.get("password", "")
    results["Password Strength"] = analyze_password(password)

    # Phishing
    url = data.get("url", "")
    results["Phishing / QR"] = detect_phishing(url)

    # Permissions
    perms = data.get("permissions", [])
    if isinstance(perms, str):
        perms = [p.strip() for p in perms.split(",")]
    results["App Permissions"] = analyze_permissions(perms)

    # WiFi
    encryption = data.get("encryption", "WPA2")
    is_public = data.get("is_public", False)
    results["WiFi Risk"] = wifi_risk(encryption, is_public)

    # Dashboard
    dashboard = build_dashboard(results)

    return jsonify({
        "results": results,
        "dashboard": dashboard
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"\n🛡 CyberShield running on port {port}\n")
    app.run(host="0.0.0.0", port=port)
