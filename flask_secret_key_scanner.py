import os
import re
import pandas as pd

# Define regex pattern for detecting Flask SECRET_KEY disclosure
SECRET_KEY_PATTERN = re.compile(r"SECRET_KEY\s*=\s*[\"'].*[\"']")

VULNERABILITY_DETAILS = {
    "name": "Flask Secret Key Disclosure",
    "description": "Hardcoded Flask SECRET_KEY values can expose sensitive information and compromise application security.",
    "recommendation": "Store the SECRET_KEY securely using environment variables or a configuration file, instead of hardcoding it in the source code."
}

def scan_for_secret_key_disclosure(directory):
    """Scans Python files for hardcoded Flask SECRET_KEY vulnerabilities."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception as e:
                    print(f"❌ Error reading {file_path}: {e}")
                    continue

                for line_no, line in enumerate(lines, start=1):
                    if SECRET_KEY_PATTERN.search(line):
                        results.append({
                            "Vulnerability": VULNERABILITY_DETAILS["name"],
                            "Line Number": line_no,
                            "File Path": file_path,
                            "Description": VULNERABILITY_DETAILS["description"],
                            "Vulnerable Code": line.strip(),
                            "Recommendation": VULNERABILITY_DETAILS["recommendation"]
                        })

    return results

def export_results_to_csv_excel(results, output_folder):
    """Exports scan results to CSV and Excel files."""
    if not results:
        print("\n✅ No Flask Secret Key vulnerabilities found!")
        return

    df = pd.DataFrame(results)
    
    csv_path = os.path.join(output_folder, "flask_secret_key_report.csv")
    excel_path = os.path.join(output_folder, "flask_secret_key_report.xlsx")
    
    df.to_csv(csv_path, index=False)
    df.to_excel(excel_path, index=False)

    print(f"\n📂 Results saved to:\n  - {csv_path}\n  - {excel_path}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for Flask Secret Key Disclosure vulnerabilities...")
    vulnerabilities_found = scan_for_secret_key_disclosure(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Potential Flask Secret Key Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line Number']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)
    
    export_results_to_csv_excel(vulnerabilities_found, folder_to_scan)

if __name__ == "__main__":
    main()
