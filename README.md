# 🛡 CyberShield — Setup & Run

## Install dependencies
```
pip install flask flask-cors
```

## Run the app
```
cd cybershield
python app.py
```

## Open in browser
```
http://localhost:5000
```

## Project Structure
```
cybershield/
├── app.py                    ← Flask backend (all API routes)
├── requirements.txt
├── templates/
│   └── index.html            ← Frontend UI
└── modules/
    ├── digital_footprint_leak_checker.py
    ├── password_strength_analyzer.py
    ├── phishing_link_qr_detector.py
    ├── rogue_app_permission_analyzer.py
    ├── public_wifi_risk_indicator.py
    └── cyber_risk_dashboard.py
```

## API Endpoints
| Method | Endpoint           | Body                              |
|--------|--------------------|-----------------------------------|
| POST   | /api/footprint     | `{ "text": "..." }`               |
| POST   | /api/password      | `{ "password": "..." }`           |
| POST   | /api/phishing      | `{ "url": "..." }`                |
| POST   | /api/permissions   | `{ "permissions": ["READ_SMS"] }` |
| POST   | /api/wifi          | `{ "encryption": "WPA2", "is_public": false }` |
| POST   | /api/scan-all      | All fields combined               |
