import os
import re
import openpyxl

def save_results_to_excel(results, output_file="sensitive_data_report.xlsx"):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Sensitive Data Findings"
    ws.append(["Vulnerability", "File Path", "Line No", "Description", "Vulnerable Code", "Recommendation"])
    
    for vuln in results:
        ws.append([
            vuln["vulnerability"],
            vuln["file_path"],
            vuln["line_no"],
            vuln["description"],
            vuln["vulnerable_code"],
            vuln["recommendation"]
        ])
    
    wb.save(output_file)
    print(f"\n✅ Results saved to {output_file}\n")

# Define patterns for detecting sensitive data exposure
SENSITIVE_DATA_PATTERNS = [
    {"name": "Hardcoded Password",
     "pattern": re.compile(r'(\bpassword\b|\bpasswd\b|\bsecret\b)\s*=\s*["\'].*["\']', re.IGNORECASE),
     "description": "Hardcoding passwords in source code exposes them to attackers.",
     "recommendation": "Store secrets in environment variables or a secure vault."},
    {"name": "Hardcoded API Key",
     "pattern": re.compile(r'(\bapi_key\b|\bapikey\b|\baccess_token\b|\bclient_secret\b)\s*=\s*["\'].*["\']', re.IGNORECASE),
     "description": "Hardcoded API keys can be stolen and misused by attackers.",
     "recommendation": "Use environment variables or configuration files."},
    {"name": "Exposed Private Key",
     "pattern": re.compile(r'-----BEGIN (RSA|DSA|EC|PRIVATE) KEY-----', re.IGNORECASE),
     "description": "Private keys should never be stored in source code repositories.",
     "recommendation": "Use secure key management solutions and never commit private keys to Git."},
    {"name": "Printing Sensitive Data",
     "pattern": re.compile(r'print\s*\(\s*(password|api_key|secret|token)\s*\)', re.IGNORECASE),
     "description": "Printing sensitive data can expose it in logs or console output.",
     "recommendation": "Avoid printing secrets; use logging with redaction mechanisms."},
    {"name": "Using Plaintext HTTP for Sensitive Data",
     "pattern": re.compile(r'requests\.(get|post|put|delete)\s*\(\s*["\']http://', re.IGNORECASE),
     "description": "Sending sensitive data over plaintext HTTP can lead to data leaks.",
     "recommendation": "Use HTTPS instead of HTTP for secure communication."}
]

def scan_for_sensitive_data(directory):
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for line_no, line in enumerate(lines, start=1):
                    for vuln in SENSITIVE_DATA_PATTERNS:
                        if vuln["pattern"].search(line):
                            results.append({
                                "vulnerability": vuln["name"],
                                "line_no": line_no,
                                "file_path": file_path,
                                "description": vuln["description"],
                                "vulnerable_code": line.strip(),
                                "recommendation": vuln["recommendation"]
                            })
    return results

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()
    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return
    print("\nScanning for sensitive data exposure vulnerabilities...")
    vulnerabilities_found = scan_for_sensitive_data(folder_to_scan)
    if vulnerabilities_found:
        print("\n🔴 Potential Sensitive Data Exposure Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['vulnerability']}")
            print(f"📍 Location: {vuln['file_path']} (Line {vuln['line_no']})")
            print(f"📝 Description: {vuln['description']}")
            print(f"⚠️ Vulnerable Code: {vuln['vulnerable_code']}")
            print(f"✅ Recommendation: {vuln['recommendation']}")
            print("-" * 80)
        save_results_to_excel(vulnerabilities_found)
    else:
        print("✅ No sensitive data exposure vulnerabilities found!")

if __name__ == "__main__":
    main()
