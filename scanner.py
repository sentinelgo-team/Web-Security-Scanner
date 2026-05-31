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
    parsed = urlparse(url)
    return bool(parsed.scheme in ["http", "https"] and parsed.netloc)

def check_security_headers(response):
    findings = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    for header in SECURITY_HEADERS:
        if header.lower() not in headers_lower:
            findings.append(f"❌ Missing Security Header: {header}")
    return findings

def extract_forms(url):
    try:
        headers = {"User-Agent": "Web-Security-Scanner/1.0"}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def generate_report(target_url):
    report = []

    report.append("=" * 70)
    report.append("              WEB SECURITY SCANNER REPORT")
    report.append("=" * 70)
    report.append(f"Target URL     : {target_url}")
    report.append(f"Scan Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Scanner Version: 1.0")
    report.append("=" * 70 + "\n")

    try:
        headers = {"User-Agent": "Web-Security-Scanner/1.0"}
        response = requests.get(target_url, headers=headers, timeout=15)
        response.raise_for_status()

        # Security Headers
        header_findings = check_security_headers(response)
        report.append("SECURITY HEADERS ANALYSIS")
        report.append("-" * 50)
        if header_findings:
            report.extend(header_findings)
        else:
            report.append("✅ All recommended security headers are present.")

        # Forms
        forms = extract_forms(target_url)
        report.append("\nFORM DISCOVERY")
        report.append("-" * 50)
        report.append(f"Forms Found    : {len(forms)}")

        if forms:
            for i, form in enumerate(forms, 1):
                action = form.get("action") or "Relative (same page)"
                method = form.get("method", "GET").upper()
                inputs = len(form.find_all(["input", "textarea", "select", "button"]))
                report.append("")
                report.append(f"Form #{i}")
                report.append(f"   Method : {method}")
                report.append(f"   Action : {action}")
                report.append(f"   Inputs : {inputs}")
        else:
            report.append("\n   No forms were detected on this page.")

        report.append("")
        report.append("=" * 70)
        report.append("End of Report")
        report.append("=" * 70)

        # Save with final newline
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(report) + "\n")

        print("\n✅ Report generated successfully!")
        print(f"📄 Report saved as: {REPORT_FILE}")

    except Exception as e:
        print(f"❌ Error during scan: {e}")

def main():
    print("=" * 70)
    print("                  WEB SECURITY SCANNER")
    print("           Basic Security Assessment Tool")
    print("=" * 70)

    target = input("\nEnter target URL: ").strip()
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not is_valid_url(target):
        print("❌ Invalid URL!")
        sys.exit(1)

    print(f"\n🔍 Scanning {target} ...\n")
    generate_report(target)

if __name__ == "__main__":
    main()
