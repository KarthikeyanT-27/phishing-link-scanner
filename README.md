🛡️ Phishing Link Scanner

A Python-based tool to detect and analyze suspicious URLs using multiple features such as URL structure, WHOIS data, and more.

✅ Features

Detects suspicious or phishing URLs based on:
URL length & path length
Domain information (via WHOIS lookup)
Presence of suspicious patterns
Uses Python, Scapy, and OpenCV for certain validations
Simple CLI-based interaction

📂 Project Structure
phishing-link-scanner/
├── phishing_scanner.py   # Main script
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation

⚙️ Installation
1️⃣ Clone the repository:
git clone https://github.com/KarthikeyanT-27/phishing-link-scanner.git
cd phishing-link-scanner

2️⃣ Create a virtual environment (optional but recommended):
python -m venv venv
source venv/bin/activate    # For Linux/Mac
venv\Scripts\activate       # For Windows

3️⃣ Install dependencies:
pip install -r requirements.txt

▶️ Usage

Run the scanner with:
python phishing_scanner.py
Enter the URL you want to check, and the tool will analyze whether it's suspicious or safe.

✅ Example
Enter a URL to scan: http://example.com/verify-login
Result: ⚠️ Suspicious - Possible phishing attempt detected!

🔍 How It Works

Feature Extraction: Collects information like:
URL length
Path length
WHOIS registration details
Rule-Based Analysis: Compares against known phishing patterns.
Scoring System: Generates a risk score based on extracted features.

🛠 Technologies Used
Python 3
python-whois
url-parser
request
