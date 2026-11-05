# CyberShield

A Flask-based cybersecurity toolkit that brings several practical security checks into one local web application.

## Features

- **Password strength analysis** — evaluates password strength and provides feedback.
- **Phishing detection** — checks submitted URLs for phishing indicators.
- **Wi-Fi risk analysis** — provides a basic assessment of Wi-Fi security risks.
- **Application permission checks** — helps review app permission risks.
- **Digital footprint scan** — brings selected digital-footprint checks together.

> CyberShield is an educational project, not a replacement for professional security testing, endpoint protection, or a dedicated threat-intelligence service. Results are indicative and should be independently verified.

## Technology

- Python
- Flask
- Flask-CORS

## Run locally

1. Clone this repository:

   ```bash
   git clone https://github.com/pavankumar-dev1/cybershield.git
   cd cybershield
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   # Windows PowerShell
   .venv\Scripts\Activate.ps1
   # macOS / Linux
   source .venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install flask flask-cors
   ```

4. Start the application:

   ```bash
   python app.py
   ```

5. Open http://127.0.0.1:5000 in your browser.

## Responsible use

Use the toolkit only on systems, URLs, networks, and data that you own or are explicitly authorized to assess. Do not treat automated results as definitive security findings.

## Project status

This repository is an ongoing learning project. Features and detection accuracy may change as the project develops.

## Author

**Pavan Kumar** · [GitHub](https://github.com/pavankumar-dev1) · [LinkedIn](https://www.linkedin.com/in/cyberpavankumar)
