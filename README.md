# Web Security Scanner

A lightweight Python-based tool for basic web security analysis that checks security headers and discovers HTML forms.

## Features

- **Security Headers Analysis**: Checks for CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Form Discovery**: Finds and analyzes HTML forms (method, action, input count)
- **Professional Reporting**: Generates detailed reports with timestamps
- **Passive Scanning**: Non-intrusive, educational use only
- **Custom User-Agent**: Uses "Web-Security-Scanner/1.0" for better compatibility
- **Fast & Reliable**: Timeout handling and error recovery

## Installation

```bash
# Clone the repository
git clone https://github.com/sentinelgo-team/Web-Security-Scanner.git
cd Web-Security-Scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Run the scanner
python scanner.py

# Follow the prompt:
# Enter target URL (e.g., https://example.com): https://httpbin.org
```

### Example Workflow
```
======================================================================
                  WEB SECURITY SCANNER
           Basic Security Assessment Tool
======================================================================

Enter target URL (e.g., https://example.com): https://httpbin.org

Scanning https://httpbin.org ...

Report generated successfully!
Report saved as: report.txt

======================================================================
              WEB SECURITY SCANNER REPORT
======================================================================
Target URL     : https://httpbin.org
Scan Date      : 2026-08-14 09:27:42
Scanner Version: 1.0
======================================================================

SECURITY HEADERS ANALYSIS
--------------------------------------------------
Missing Security Header: Content-Security-Policy
Missing Security Header: X-Frame-Options
Missing Security Header: Strict-Transport-Security
Missing Security Header: X-Content-Type-Options
Missing Security Header: Referrer-Policy
Missing Security Header: Permissions-Policy

FORM DISCOVERY
--------------------------------------------------
Forms Found    : 0

No forms were detected on this page.

======================================================================
END OF REPORT
======================================================================
```

## Requirements

- Python 3.x
- requests
- beautifulsoup4

Install via:
```bash
pip install -r requirements.txt
```

## Important Notes

- **Educational Use Only**: This tool is for learning and demonstration purposes
- **Get Permission**: Always obtain authorization before scanning websites you don't own
- **Passive Scanning**: Performs only header analysis and form discovery (no exploitation)
- **Respect Rate Limits**: Be considerate when scanning websites

## Project Structure

```
Web-Security-Scanner/
├── scanner.py          # Main scanner application
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── report.txt          # Generated security reports
��── .git/               # Version control
```

## How It Works

1. **URL Validation**: Checks if input is a valid HTTP/HTTPS URL
2. **Header Analysis**: Fetches target URL and examines security headers
3. **Form Detection**: Parses HTML to find and analyze forms
4. **Report Generation**: Creates formatted report with findings
5. **Output**: Saves to `report.txt` and optionally displays in terminal

## Customization

Adjust these constants in `scanner.py`:
- `REPORT_FILE`: Output filename (default: "report.txt")
- `SECURITY_HEADERS`: List of headers to check
- Timeouts: Modify request timeout values (currently 30 seconds)

## Support

For issues or questions, please open an issue in the GitHub repository.

---

**Happy Scanning!**

### About the Symbols (Emojis) Previously Used

In an earlier version of this README, emoji symbols were used to visually highlight sections and improve readability. These symbols were purely decorative and served no functional purpose in the scanner's operation. They have been removed to maintain a clean, professional document suitable for all audiences. The meanings of the symbols were:

- �����: Web Security Scanner (project title)
- ����: Features section
- �����: Security Headers Analysis
- �����: Form Discovery
- �����: Professional Reporting
- ��������: Passive Scanning / Educational Use
- �����: Custom User-Agent
- �����: Fast & Reliable
- �����: Installation
- �����: Usage
- ��������: Important Notes
- �����: Project Structure
- ��������: How It Works
- �����: Customization
- �����: Support

These symbols were optional and have been removed per request.