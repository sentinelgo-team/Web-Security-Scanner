import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import sys
from datetime import datetime

REPORT_FILE = "report.txt"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def is_valid_url(url):
    """Validate URL format"""
    parsed = urlparse(url)
    return bool(parsed.scheme in ["http", "https"] and parsed.netloc)

def check_security_headers(response):
    """Check for important security headers"""
    findings = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    
    for header in SECURITY_HEADERS:
        if header.lower() not in headers_lower:
            findings.append(f"Missing Security Header: {header}")
    return findings

def extract_forms(url):
    """Extract all forms from the webpage"""
    try:
        headers = {"User-Agent": "Web-Security-Scanner/1.0"}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        return forms, response
    except Exception as e:
        print(f"Error extracting forms: {e}")
        return [], None

def generate_report(target_url):
    """Generate security scan report"""
    report = []

    report.append("=" * 65)
    report.append("              WEB SECURITY SCANNER REPORT")
    report.append("=" * 65)
    report.append(f"Target URL     : {target_url}")
    report.append(f"Scan Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Scanner Version: 1.0")
    report.append("=" * 65 + "\n")

    try:
        headers = {"User-Agent": "Web-Security-Scanner/1.0"}
        response = requests.get(target_url, headers=headers, timeout=10)
        response.raise_for_status()

        # Security Headers Analysis
        header_findings = check_security_headers(response)

        report.append("SECURITY HEADERS ANALYSIS")
        report.append("-" * 45)
        if header_findings:
            for finding in header_findings:
                report.append(f"❌ {finding}")
        else:
            report.append("✅ All recommended security headers are present.")

        # Form Discovery
        forms, _ = extract_forms(target_url)

        report.append("\nFORM DISCOVERY")
        report.append("-" * 45)
        report.append(f"Forms Found    : {len(forms)}")

        for i, form in enumerate(forms, 1):
            action = form.get("action", "No action attribute")
            method = form.get("method", "GET").upper()
            inputs = len(form.find_all(['input', 'textarea', 'select', 'button']))
            report.append(f"\nForm #{i}")
            report.append(f"   Method : {method}")
            report.append(f"   Action : {action if action else 'Relative (same page)'}")
            report.append(f"   Inputs : {inputs}")

        # Save Report
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(report))

        print("\n✅ Report generated successfully!")
        print(f"📄 Report saved as: {REPORT_FILE}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error accessing URL: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def main():
    print("=" * 65)
    print("                  WEB SECURITY SCANNER")
    print("           Basic Security Assessment Tool")
    print("=" * 65)

    target = input("\nEnter target URL (e.g., https://example.com): ").strip()

    if not target:
        print("❌ URL cannot be empty.")
        sys.exit(1)

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not is_valid_url(target):
        print("❌ Please enter a valid URL.")
        sys.exit(1)

    print(f"\n🔍 Scanning {target} ...\n")
    generate_report(target)

if __name__ == "__main__":
    main()