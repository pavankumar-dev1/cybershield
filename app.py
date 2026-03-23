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

# ── Serve frontend ────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/footprint", methods=["POST"])
def api_footprint():
    data = request.get_json()
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "No text provided"}), 400
    return jsonify(check_digital_footprint(text))

@app.route("/api/password", methods=["POST"])
def api_password():
    data = request.get_json()
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    return jsonify(analyze_password(password))

@app.route("/api/phishing", methods=["POST"])
def api_phishing():
    data = request.get_json()
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(detect_phishing(url))

@app.route("/api/permissions", methods=["POST"])
def api_permissions():
    data = request.get_json()
    perms = data.get("permissions", [])
    if isinstance(perms, str):
        perms = [p.strip() for p in perms.split(",")]
    return jsonify(analyze_permissions(perms))

@app.route("/api/wifi", methods=["POST"])
def api_wifi():
    data = request.get_json()
    encryption = data.get("encryption", "WPA2")
    is_public = data.get("is_public", False)
    return jsonify(wifi_risk(encryption, is_public))

@app.route("/api/scan-all", methods=["POST"])
def api_scan_all():
    data = request.get_json()

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

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"\n🛡 CyberShield running on port {port}\n")
    app.run(host="0.0.0.0", port=port)
