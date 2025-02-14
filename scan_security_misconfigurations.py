import os
import re
import csv
import pandas as pd

# Define patterns for detecting security misconfigurations
SECURITY_MISCONFIGURATIONS = [
    {
        "name": "Flask Debug Mode Enabled",
        "pattern": re.compile(r'Flask\(\s*\)\.run\(\s*debug\s*=\s*True', re.IGNORECASE),
        "description": "Running Flask in debug mode can expose sensitive information.",
        "recommendation": "Disable debug mode in production by setting `debug=False` or using `FLASK_ENV=production`."
    },
    {
        "name": "Django Debug Mode Enabled",
        "pattern": re.compile(r'DEBUG\s*=\s*True', re.IGNORECASE),
        "description": "Debug mode in Django exposes sensitive error messages.",
        "recommendation": "Set `DEBUG = False` in production settings."
    },
    {
        "name": "Use of eval() Function",
        "pattern": re.compile(r'\beval\s*\(', re.IGNORECASE),
        "description": "The `eval()` function allows arbitrary code execution, leading to security risks.",
        "recommendation": "Use `ast.literal_eval()` if parsing literals, or alternative safe parsing methods."
    },
    {
        "name": "Use of exec() Function",
        "pattern": re.compile(r'\bexec\s*\(', re.IGNORECASE),
        "description": "The `exec()` function can execute arbitrary code, leading to potential command injection.",
        "recommendation": "Avoid using `exec()`; consider safer alternatives like direct function calls."
    },
    {
        "name": "Hardcoded Default Credentials",
        "pattern": re.compile(r'(\buser\b|\busername\b)\s*=\s*["\']admin["\'].*(\bpassword\b|\bpasswd\b)\s*=\s*["\'].*["\']', re.IGNORECASE),
        "description": "Default credentials make it easier for attackers to gain unauthorized access.",
        "recommendation": "Remove hardcoded credentials and use environment variables or a secure secrets manager."
    },
    {
        "name": "Insecure Cookie Configuration",
        "pattern": re.compile(r'set_cookie\s*\(.*secure\s*=\s*False', re.IGNORECASE),
        "description": "Insecure cookies can be intercepted over HTTP, leading to session hijacking.",
        "recommendation": "Set `secure=True` and `httponly=True` for cookies to enhance security."
    },
    {
        "name": "Use of Weak Hashing Algorithm (MD5)",
        "pattern": re.compile(r'hashlib\.md5\s*\(', re.IGNORECASE),
        "description": "MD5 is a weak hashing algorithm and is vulnerable to collision attacks.",
        "recommendation": "Use stronger hashing algorithms like SHA-256 or bcrypt for password hashing."
    },
    {
        "name": "Use of Weak Hashing Algorithm (SHA1)",
        "pattern": re.compile(r'hashlib\.sha1\s*\(', re.IGNORECASE),
        "description": "SHA-1 is deprecated due to collision vulnerabilities.",
        "recommendation": "Use SHA-256 or bcrypt for better security."
    },
    {
        "name": "Verbose Error Message",
        "pattern": re.compile(r'except\s*Exception\s+as\s+e:\s*print\s*\(e\)', re.IGNORECASE),
        "description": "Printing full exception details can expose internal logic and sensitive information.",
        "recommendation": "Use logging with redaction instead of printing errors directly."
    }
]

def scan_for_misconfigurations(directory):
    """Scans Python files for security misconfigurations and returns detailed reports."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in SECURITY_MISCONFIGURATIONS:
                        match = vuln["pattern"].search(line)
                        if match:
                            results.append({
                                "Vulnerability": vuln["name"],
                                "Line No": line_no,
                                "File Path": file_path,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })

    return results

def export_results_to_csv(results, csv_filename="security_scan_results.csv"):
    """Exports scan results to a CSV file."""
    with open(csv_filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"📂 Results saved to {csv_filename}")

def export_results_to_excel(results, excel_filename="security_scan_results.xlsx"):
    """Exports scan results to an Excel file."""
    df = pd.DataFrame(results)
    df.to_excel(excel_filename, index=False)
    print(f"📂 Results saved to {excel_filename}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for security misconfigurations...")
    vulnerabilities_found = scan_for_misconfigurations(folder_to_scan)

    if vulnerabilities_found:
        print("\n🔴 Potential Security Misconfiguration Issues Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)

        # Export results
        export_results_to_csv(vulnerabilities_found)
        export_results_to_excel(vulnerabilities_found)

    else:
        print("✅ No security misconfiguration vulnerabilities found!")

if __name__ == "__main__":
    main()
