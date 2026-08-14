import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import sys

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
    return parsed.scheme in ["http", "https"] and bool(parsed.netloc)

def check_security_headers(response):
    """Check for important security headers"""
    findings = []
    headers_lower = {header.lower() for header in response.headers.keys()}
    
    for header in SECURITY_HEADERS:
        if header.lower() not in headers_lower:
            findings.append(f"Missing Security Header: {header}")
    
    return findings

def extract_forms(url):
    """Extract all forms from the webpage"""
    try:
        headers = {
            "User-Agent": "Web-Security-Scanner/1.0"
        }
        
        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )
        
        response.raise_for_status()
        
        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )
        
        return soup.find_all("form")
        
    except Exception as e:
        print(f"Form extraction error: {e}")
        return []

def generate_report(target_url):
    """Generate security scan report"""
    report = []
    
    report.append("=" * 70)
    report.append("              WEB SECURITY SCANNER REPORT")
    report.append("=" * 70)
    report.append(f"Target URL     : {target_url}")
    report.append(
        f"Scan Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    report.append("Scanner Version: 1.0")
    report.append("=" * 70)
    report.append("")
    
    try:
        headers = {
            "User-Agent": "Web-Security-Scanner/1.0"
        }
        
        response = requests.get(
            target_url,
            headers=headers,
            timeout=30
        )
        
        response.raise_for_status()
        
        # Security Header Analysis
        report.append("SECURITY HEADERS ANALYSIS")
        report.append("-" * 50)
        
        findings = check_security_headers(response)
        
        if findings:
            report.extend(findings)
        else:
            report.append(
                "All recommended security headers are present."
            )
        
        report.append("")
        
        # Form Discovery
        forms = extract_forms(target_url)
        
        report.append("FORM DISCOVERY")
        report.append("-" * 50)
        report.append(f"Forms Found    : {len(forms)}")
        
        if forms:
            for i, form in enumerate(forms, start=1):
                
                action = (
                    form.get("action")
                    if form.get("action")
                    else "Relative (same page)"
                )
                
                method = form.get(
                    "method",
                    "GET"
                ).upper()
                
                inputs = len(
                    form.find_all(
                        ["input", "textarea", "select", "button"]
                    )
                )
                
                report.append("")
                report.append(f"Form #{i}")
                report.append(f"   Method : {method}")
                report.append(f"   Action : {action}")
                report.append(f"   Inputs : {inputs}")
        else:
            report.append("")
            report.append(
                "No forms were detected on this page."
            )
        
        report.append("")
        report.append("=" * 70)
        report.append("END OF REPORT")
        report.append("=" * 70)
        
        # Save Report
        with open(REPORT_FILE, "w", encoding="utf-8") as file:
            file.write("\n".join(report))
            file.write("\n")
        
        print("\nReport generated successfully!")
        print(f"Report saved as: {REPORT_FILE}")
        
        # Optional: Display Report
        print("\n" + "\n".join(report))
        
    except requests.exceptions.Timeout:
        print(
            "Connection timed out. "
            "Try another website or check internet connectivity."
        )
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
    
    except Exception as e:
        print(f"Unexpected Error: {e}")

def main():
    print("=" * 70)
    print("                  WEB SECURITY SCANNER")
    print("           Basic Security Assessment Tool")
    print("=" * 70)
    
    target = input(
        "\nEnter target URL (e.g., https://example.com): "
    ).strip()
    
    if not target:
        print("URL cannot be empty.")
        sys.exit(1)
    
    if not target.startswith(
        ("http://", "https://")
    ):
        target = "https://" + target
    
    if not is_valid_url(target):
        print("Invalid URL.")
        sys.exit(1)
    
    print(f"\nScanning {target} ...")
    generate_report(target)

if __name__ == "__main__":
    main()