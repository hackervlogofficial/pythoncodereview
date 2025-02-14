import os
import re
import csv
import argparse
import pandas as pd
from colorama import Fore, Style

# Define patterns to detect missing SSL/TLS hostname verification
INSECURE_SSL_PATTERNS = [
    {
        "name": "Missing SSL Hostname Verification (ssl module)",
        "pattern": re.compile(r'ssl\.create_default_context\s*\(\s*\)', re.IGNORECASE),
        "description": "SSL context should verify server hostnames to prevent MITM attacks.",
        "recommendation": "Use ssl.create_default_context() and set check_hostname = True."
    },
    {
        "name": "Disabling SSL Certificate Verification",
        "pattern": re.compile(r'ssl\.create_default_context\s*\(\s*ssl\.Purpose\.CLIENT_AUTH\s*\)', re.IGNORECASE),
        "description": "Client authentication without verifying the server certificate is insecure.",
        "recommendation": "Set check_hostname=True and verify_mode=ssl.CERT_REQUIRED."
    },
    {
        "name": "Requests Module with SSL Verification Disabled",
        "pattern": re.compile(r'requests\.\w+\s*\(.*verify\s*=\s*False.*\)', re.IGNORECASE),
        "description": "Disabling SSL verification in requests allows MITM attacks.",
        "recommendation": "Set verify=True or use a valid CA certificate bundle."
    },
    {
        "name": "urllib3 Disabling SSL Warnings",
        "pattern": re.compile(r'urllib3\.disable_warnings\s*\(\s*urllib3\.exceptions\.InsecureRequestWarning\s*\)', re.IGNORECASE),
        "description": "Disabling SSL warnings may hide critical security issues.",
        "recommendation": "Fix SSL issues instead of suppressing warnings."
    },
    {
        "name": "Unverified HTTPS Connection (urllib)",
        "pattern": re.compile(r'urllib\.request\.urlopen\s*\(.*context\s*=\s*ssl\._create_unverified_context\(\)\s*\)', re.IGNORECASE),
        "description": "Unverified SSL context allows connections without certificate validation.",
        "recommendation": "Use ssl.create_default_context() instead."
    }
]

def scan_for_insecure_ssl(directory):
    """Scans Python files for missing SSL/TLS hostname verification."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        for vuln in INSECURE_SSL_PATTERNS:
                            if vuln["pattern"].search(line):
                                results.append({
                                    "vulnerability": vuln["name"],
                                    "file_path": file_path,
                                    "line_no": line_no,
                                    "description": vuln["description"],
                                    "vulnerable_code": line.strip(),
                                    "recommendation": vuln["recommendation"]
                                })
    return results

def save_results_to_csv(results, output_path):
    """Save scan results to a CSV file."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(Fore.GREEN + f"✅ Results saved to CSV: {output_path}" + Style.RESET_ALL)

def save_results_to_excel(results, output_path):
    """Save scan results to an Excel file."""
    df = pd.DataFrame(results)
    df.to_excel(output_path, index=False)
    print(Fore.GREEN + f"✅ Results saved to Excel: {output_path}" + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description="Scan Python code for missing SSL/TLS hostname verification.")
    parser.add_argument("directory", help="Path to the folder containing Python files.")
    parser.add_argument("--csv", help="Export results to a CSV file", default="ssl_scan_results.csv")
    parser.add_argument("--excel", help="Export results to an Excel file", default="ssl_scan_results.xlsx")
    args = parser.parse_args()

    if not os.path.exists(args.directory):
        print(Fore.RED + "❌ Invalid folder path! Please enter a valid path." + Style.RESET_ALL)
        return

    print(Fore.CYAN + "\n🔍 Scanning for SSL/TLS security issues...\n" + Style.RESET_ALL)
    vulnerabilities_found = scan_for_insecure_ssl(args.directory)

    if vulnerabilities_found:
        print(Fore.RED + "\n🚨 Insecure SSL/TLS Configurations Found:" + Style.RESET_ALL)
        for vuln in vulnerabilities_found:
            print(f"\n📌 {Fore.YELLOW}Vulnerability: {vuln['vulnerability']}{Style.RESET_ALL}")
            print(f"📍 Location: {vuln['file_path']} (Line {vuln['line_no']})")
            print(f"📝 Description: {vuln['description']}")
            print(f"⚠️ Vulnerable Code: {Fore.RED}{vuln['vulnerable_code']}{Style.RESET_ALL}")
            print(f"✅ Recommendation: {Fore.GREEN}{vuln['recommendation']}{Style.RESET_ALL}")
            print("-" * 80)
        
        # Save results to CSV and Excel
        save_results_to_csv(vulnerabilities_found, args.csv)
        save_results_to_excel(vulnerabilities_found, args.excel)
    else:
        print(Fore.GREEN + "✅ No SSL/TLS verification issues found!" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
