import os
import re
import csv
import pandas as pd

# Define patterns to detect hard-coded credentials
VULNERABILITY_PATTERNS = [
    {
        "name": "Hard-Coded Password",
        "pattern": re.compile(r'password\s*=\s*[\'"].+[\'"]', re.IGNORECASE),
        "description": "Hard-coded passwords can be extracted from the source code, leading to unauthorized access.",
        "recommendation": "Store passwords in environment variables or use a secure vault."
    },
    {
        "name": "Hard-Coded API Key",
        "pattern": re.compile(r'api[_]?key\s*=\s*[\'"].+[\'"]', re.IGNORECASE),
        "description": "Exposing API keys in source code allows attackers to abuse services.",
        "recommendation": "Store API keys in environment variables and retrieve them securely."
    },
    {
        "name": "Hard-Coded Token",
        "pattern": re.compile(r'token\s*=\s*[\'"].+[\'"]', re.IGNORECASE),
        "description": "Hard-coded authentication tokens can be stolen and misused.",
        "recommendation": "Use secure storage for tokens, such as a secrets manager."
    },
    {
        "name": "Hard-Coded Secret Key",
        "pattern": re.compile(r'secret\s*=\s*[\'"].+[\'"]', re.IGNORECASE),
        "description": "Hard-coded secret keys can compromise security mechanisms.",
        "recommendation": "Store secret keys in environment variables or a configuration file."
    },
    {
        "name": "Hard-Coded DB Connection String",
        "pattern": re.compile(r'(\b(DB_CONNECTION_STRING|conn_string)\b\s*=\s*[\'"].+[\'"])', re.IGNORECASE),
        "description": "Database connection strings should not be hardcoded as they expose sensitive credentials.",
        "recommendation": "Use environment variables or a configuration management system to store credentials securely."
    },
    {
        "name": "Hard-Coded Client Secret",
        "pattern": re.compile(r'client_secret\s*=\s*[\'"].+[\'"]', re.IGNORECASE),
        "description": "Client secrets should be stored securely and not hardcoded in source code.",
        "recommendation": "Store client secrets in a vault or secure storage."
    }
]

# File extensions to scan
FILE_EXTENSIONS = [".py", ".env", ".config", ".ini", ".json"]

def scan_for_vulnerabilities(directory):
    """Scans files for hard-coded credentials."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in FILE_EXTENSIONS):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    if line.strip().startswith("#") or line.strip().startswith("//"):  # Ignore comments
                        continue

                    for vuln in VULNERABILITY_PATTERNS:
                        match = vuln["pattern"].search(line)
                        if match:
                            results.append({
                                "Vulnerability": vuln["name"],
                                "File": file_path,
                                "Line": line_no,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })

    return results

def export_results_csv(results, output_path="vulnerabilities.csv"):
    """Exports results to CSV."""
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["Vulnerability", "File", "Line", "Description", "Vulnerable Code", "Recommendation"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"📄 Results exported to CSV: {output_path}")

def export_results_excel(results, output_path="vulnerabilities.xlsx"):
    """Exports results to Excel."""
    df = pd.DataFrame(results)
    df.to_excel(output_path, index=False)
    print(f"📊 Results exported to Excel: {output_path}")

def main():
    folder_to_scan = input("Enter the folder path containing source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for hard-coded credentials...")
    vulnerabilities_found = scan_for_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Hard-Coded Credential Vulnerabilities Found!")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File']} (Line {vuln['Line']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)

        # Export to CSV & Excel
        export_results_csv(vulnerabilities_found)
        export_results_excel(vulnerabilities_found)
    else:
        print("✅ No hard-coded credential vulnerabilities found!")

if __name__ == "__main__":
    main()
