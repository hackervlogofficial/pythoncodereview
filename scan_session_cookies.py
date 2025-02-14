import os
import re
import pandas as pd

# Define patterns to detect insecure session cookie assignments
SESSION_VULNERABILITY_PATTERNS = [
    {
        "name": "Session Cookie from Untrusted GET Input",
        "pattern": re.compile(r'session\["[^"]+"\]\s*=\s*request\.args\.get', re.IGNORECASE),
        "description": "Session cookies should not be set based on GET parameters, as they can be easily manipulated.",
        "recommendation": "Use secure, random session identifiers instead of user input.",
        "severity": "High"
    },
    {
        "name": "Session Cookie from Untrusted POST Input",
        "pattern": re.compile(r'session\["[^"]+"\]\s*=\s*request\.form\.get', re.IGNORECASE),
        "description": "Session cookies should not be set based on POST parameters, as they may be tampered with.",
        "recommendation": "Generate session cookies securely using cryptographic methods.",
        "severity": "Medium"
    },
    {
        "name": "Session Cookie from JSON Request Input",
        "pattern": re.compile(r'session\["[^"]+"\]\s*=\s*request\.json\.get', re.IGNORECASE),
        "description": "Session cookies should not be set based on JSON request input.",
        "recommendation": "Ensure session cookies are generated securely, avoiding user-controlled input.",
        "severity": "Medium"
    },
    {
        "name": "Session Cookie from Untrusted Cookie Input",
        "pattern": re.compile(r'session\["[^"]+"\]\s*=\s*request\.cookies\.get', re.IGNORECASE),
        "description": "Session cookies should not be assigned directly from user-controlled cookies.",
        "recommendation": "Use a secure server-side session mechanism instead.",
        "severity": "High"
    }
]

def scan_for_session_cookie_issues(directory):
    """Scans Python files for insecure session cookie assignments."""
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                
                for line_no, line in enumerate(lines, start=1):
                    for vuln in SESSION_VULNERABILITY_PATTERNS:
                        if vuln["pattern"].search(line):
                            results.append({
                                "Vulnerability": vuln["name"],
                                "Severity": vuln["severity"],
                                "File Path": file_path,
                                "Line No": line_no,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })
    return results

def save_results_to_csv_excel(results):
    """Saves the scan results to CSV and Excel files."""
    if results:
        df = pd.DataFrame(results)
        df.to_csv("session_vulnerabilities.csv", index=False)
        df.to_excel("session_vulnerabilities.xlsx", index=False)
        print("\n📂 Results saved as 'session_vulnerabilities.csv' and 'session_vulnerabilities.xlsx'.")
    else:
        print("\n✅ No insecure session cookie assignments found!")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()
    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for insecure session cookie assignments...")
    vulnerabilities_found = scan_for_session_cookie_issues(folder_to_scan)
    save_results_to_csv_excel(vulnerabilities_found)

if __name__ == "__main__":
    main()
