# Web Security Scanner

A lightweight Python-based tool that performs basic web security analysis by checking security headers and discovering forms.

## Features

- Security headers analysis (CSP, HSTS, X-Frame-Options, etc.)
- Form discovery with method, action, and input count
- Professional report generation (`report.txt`)
- Custom User-Agent header for better compatibility
- Clean error handling and URL validation
- Non-intrusive / passive scanning

## Technologies

- Python 3
- Requests
- BeautifulSoup4

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py
```

## Important Notes

- This tool is for **educational and demonstration purposes only**.
- It performs only passive scanning (no exploitation or aggressive testing).
- Always obtain permission before scanning websites you do not own.

## GitHub Description
Python-based web security scanner for security header analysis, form discovery, and automated report generation.