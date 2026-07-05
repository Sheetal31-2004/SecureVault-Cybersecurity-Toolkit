# 🔐 SecureVault – Cybersecurity Toolkit

SecureVault is a web-based cybersecurity toolkit developed using Python and Flask that brings together multiple security utilities into a single platform. It provides network scanning, file analysis, cryptographic operations, hash generation, and automated forensic reporting through an intuitive web interface.

The project was designed to demonstrate practical cybersecurity concepts by integrating commonly used security operations into a centralized application suitable for learning, demonstrations, and academic projects.

---

## Key Features

- Secure user authentication and session management
- Network scanning with multiple scan profiles
- File scanning and analysis
- File encryption and decryption
- SHA-256 hash generation and verification
- Activity logging and monitoring
- Automated forensic report generation
- Interactive dashboard for security operations
- Responsive and user-friendly interface

---

## Technology Stack

### Backend
- Python
- Flask

### Frontend
- HTML5
- CSS3
- JavaScript
- Bootstrap

### Database
- SQLite

### Additional Libraries
- ReportLab
- Cryptography
- Requests
- Werkzeug

---

## Project Structure

```
SecureVault-Cybersecurity-Toolkit/
│
├── static/                 # CSS, JavaScript, Images
├── templates/              # HTML Templates
├── uploads/                # Uploaded files
│
├── app.py                  # Main Flask application
├── scanner.py              # Network scanning module
├── file_scanner.py         # File analysis module
├── crypto_utils.py         # Encryption & hashing utilities
├── database.py             # Database operations
├── scan_profiles.py        # Scan configurations
│
├── requirements.txt
└── README.md
```

---

## Core Modules

### Network Scanner
Performs network reconnaissance using configurable scan profiles and displays the detected services through the dashboard.

### File Scanner
Analyzes uploaded files and processes them for further security inspection.

### Encryption & Decryption
Provides secure encryption and decryption functionality to protect sensitive files.

### Hash Generator
Generates SHA-256 hashes for integrity verification and validation.

### Dashboard
Provides a centralized interface to access all security utilities and monitor activities.

### Report Generator
Creates structured forensic reports that summarize scan results and security findings.

---

## Installation

Clone the repository

```bash
git clone https://github.com/Sheetal31-2004/SecureVault-Cybersecurity-Toolkit.git
```

Move into the project directory

```bash
cd SecureVault-Cybersecurity-Toolkit
```

Install the required dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python app.py
```

Open your browser and visit

```
http://127.0.0.1:5000
```

---

## Screenshots

Project screenshots will be added soon.

---

## Future Enhancements

- Malware detection integration
- AI-assisted threat analysis
- Vulnerability assessment reports
- Multi-user role management
- Cloud storage support
- Real-time monitoring dashboard
- PDF report customization

---

## Learning Outcomes

This project demonstrates practical implementation of:

- Secure web application development
- Network scanning concepts
- Cryptography fundamentals
- Digital evidence reporting
- File integrity verification
- Secure authentication
- Python Flask application development

---

## Author
Sheetal Redekar
Interested in Cybersecurity, Digital Forensics, Network Security, and Secure Software Development.

---

## License

This project is intended for educational and learning purposes.
