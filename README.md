# Secure Client-Server Application Using SSL/TLS

A Python-based client-server application demonstrating secure communication over TLS, password authentication, message integrity verification, and security event logging.

## Features

- Secure client-server communication using SSL/TLS.
- TLS 1.2 minimum version.
- Certificate-based server authentication.
- Username and password authentication.
- Password hashing using bcrypt.
- HMAC-SHA256 message integrity verification.
- Security event logging.
- Automated tests using pytest.
- Log analysis and JSON report generation.

## Project Structure

    secure-tls-application/
    ├── certs/
    │   ├── ca.crt
    │   └── server.crt
    ├── logs/
    │   └── .gitkeep
    ├── scripts/
    │   └── gencerts.sh
    ├── tests/
    │   ├── conftest.py
    │   ├── test_auth.py
    │   ├── test_integrity.py
    │   └── test_tls.py
    ├── .gitignore
    ├── analyze_logs.py
    ├── client.py
    ├── requirements.txt
    └── server.py

## Requirements

- Python 3.10 or newer
- OpenSSL
- pip

## Installation

Clone the repository:

    git clone https://github.com/Lepilin-Dmytro/secure-tls-application.git
    cd secure-tls-application

Create a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## Certificate Generation

Generate the local CA and server certificate:

    chmod +x scripts/gencerts.sh
    ./scripts/gencerts.sh

The script generates certificates and private keys. Private keys must not be uploaded to GitHub.

## User Account Setup

Create a user account with a bcrypt password hash:

    python -c 'import bcrypt,json,getpass; u=input("Username: "); p=getpass.getpass("Password: "); h=bcrypt.hashpw(p.encode(),bcrypt.gensalt()).decode(); json.dump({u:h},open("users.json","w"),indent=2)'

The users.json file is stored locally and excluded from Git.

## Running the Application

Terminal 1 — start the server:

    source .venv/bin/activate
    python server.py

Terminal 2 — start the client:

    source .venv/bin/activate
    python client.py

Enter the username and password created earlier.

After successful authentication, messages can be exchanged securely. Enter /exit to close the client.

## Automated Security Tests

Run the tests:

    python -m pytest -v

The test suite checks:

- TLS connection and certificate verification.
- Successful authentication.
- Rejection of invalid credentials.
- Valid message integrity.
- Rejection of messages with an invalid HMAC.

## Log Analysis

Run the log analyzer:

    python analyze_logs.py

The analyzer counts security events and detects repeated failed login attempts.

The report is saved to logs/analysis_report.json.

## Security Mechanisms

| Mechanism | Purpose |
|---|---|
| SSL/TLS | Protects data during transmission |
| X.509 certificates | Verifies server identity |
| bcrypt | Secure password hashing |
| HMAC-SHA256 | Message integrity verification |
| Event logging | Records security events |
| pytest | Automated security testing |

## Limitations

This project is an educational demonstration of basic client-server security mechanisms. It is not intended for production use.

## Author

Dmytro Lepilin

Educational project — Secure Client-Server Application Using SSL/TLS.
