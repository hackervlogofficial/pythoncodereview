import os
import re
import sys
import pandas as pd

def scan_ldap_issues(directory):
    """Scans Python files for unauthenticated LDAP connections."""
    vulnerabilities = []

    ldap_patterns = [
        {
            "name": "Unauthenticated LDAP Connection",
            "pattern": re.compile(r'ldap3\.Server\(\s*[\"\'].*[\"\']\s*\)'),
            "description": "LDAP connections should require authentication to prevent unauthorized access.",
            "recommendation": "Ensure that LDAP connections use authentication methods like SIMPLE, NTLM, or SASL." 
        },
        {
            "name": "Potential Anonymous LDAP Bind",
            "pattern": re.compile(r'ldap3\.Connection\(\s*server\s*,\s*user=None\s*,\s*password=None'),
            "description": "Anonymous LDAP binds allow unauthorized access and should be avoided.",
            "recommendation": "Use proper authentication credentials in the LDAP connection." 
        }
    ]

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception as e:
                    print(f"⚠️ Error reading file {file_path}: {e}")
                    continue

                for line_no, line in enumerate(lines, start=1):
                    for vuln in ldap_patterns:
                        if vuln["pattern"].search(line):
                            vulnerabilities.append({
                                "Vulnerability": vuln["name"],
                                "Line Number": line_no,
                                "File Path": file_path,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })
    
    return vulnerabilities

def save_results_to_files(results, output_directory):
    """Saves scan results to an Excel file and a CSV file."""
    if not results:
        print("✅ No LDAP vulnerabilities found. No report generated.")
        return
    
    df = pd.DataFrame(results)
    os.makedirs(output_directory, exist_ok=True)

    excel_path = os.path.join(output_directory, "ldap_vulnerabilities_report.xlsx")
    csv_path = os.path.join(output_directory, "ldap_vulnerabilities_report.csv")

    try:
        df.to_excel(excel_path, index=False)
        df.to_csv(csv_path, index=False)
        print(f"\n📂 Reports saved successfully:")
        print(f"📊 Excel File: {excel_path}")
        print(f"📜 CSV File: {csv_path}")
    except Exception as e:
        print(f"❌ Error saving reports: {e}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()
    
    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for LDAP authentication issues...")
    vulnerabilities_found = scan_ldap_issues(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 LDAP Authentication Issues Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line Number']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)

    save_results_to_files(vulnerabilities_found, folder_to_scan)

if __name__ == "__main__":
    main()
