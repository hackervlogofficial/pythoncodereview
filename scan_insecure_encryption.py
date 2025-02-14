import os
import re
import csv
import argparse
import pandas as pd
from colorama import Fore, Style

# Define patterns to detect insecure encryption modes and padding
INSECURE_ENCRYPTION_PATTERNS = [
    {
        "name": "Use of Insecure AES Mode (ECB)",
        "pattern": re.compile(r'AES\.new\s*\(\s*\w+\s*,\s*AES\.MODE_ECB', re.IGNORECASE),
        "description": "ECB mode is deterministic and leaks patterns in encrypted data.",
        "recommendation": "Use AES with GCM (AES.MODE_GCM) instead."
    },
    {
        "name": "Use of Insecure AES Mode (CBC) Without IV",
        "pattern": re.compile(r'AES\.new\s*\(\s*\w+\s*,\s*AES\.MODE_CBC\s*\)', re.IGNORECASE),
        "description": "CBC mode requires a secure IV to prevent attacks.",
        "recommendation": "Ensure an IV is securely generated and passed to CBC mode."
    },
    {
        "name": "Use of Weak RSA Padding (PKCS#1 v1.5)",
        "pattern": re.compile(r'PKCS1_v1_5\.new\s*\(', re.IGNORECASE),
        "description": "PKCS#1 v1.5 padding is vulnerable to padding oracle attacks.",
        "recommendation": "Use RSA with OAEP padding (PKCS1_OAEP) instead."
    },
    {
        "name": "Use of Hardcoded IV",
        "pattern": re.compile(r'iv\s*=\s*b?[\'"]\x00{16}[\'"]', re.IGNORECASE),
        "description": "Hardcoded IVs make AES-CBC predictable and easier to attack.",
        "recommendation": "Generate a random IV using os.urandom(16) and store it securely."
    }
]

def scan_for_insecure_encryption(directory):
    """Scans Python files for encryption algorithms using insecure modes or padding."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        for vuln in INSECURE_ENCRYPTION_PATTERNS:
                            match = vuln["pattern"].search(line)
                            if match:
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
    parser = argparse.ArgumentParser(description="Scan Python code for insecure encryption practices.")
    parser.add_argument("directory", help="Path to the folder containing Python files.")
    parser.add_argument("--csv", help="Export results to a CSV file", default="encryption_scan_results.csv")
    parser.add_argument("--excel", help="Export results to an Excel file", default="encryption_scan_results.xlsx")
    args = parser.parse_args()

    if not os.path.exists(args.directory):
        print(Fore.RED + "❌ Invalid folder path! Please enter a valid path." + Style.RESET_ALL)
        return

    print(Fore.CYAN + "\n🔍 Scanning for insecure encryption usage...\n" + Style.RESET_ALL)
    vulnerabilities_found = scan_for_insecure_encryption(args.directory)

    if vulnerabilities_found:
        print(Fore.RED + "\n🚨 Insecure Encryption Algorithms Found:" + Style.RESET_ALL)
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
        print(Fore.GREEN + "✅ No insecure encryption usage found!" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
