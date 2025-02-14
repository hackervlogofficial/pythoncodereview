import os
import re
import pandas as pd

# Define patterns for insecure XML parsing methods
XXE_VULNERABILITIES = [
    {
        "name": "Insecure XML Parsing (xml.etree.ElementTree)",
        "pattern": re.compile(r'xml\.etree\.ElementTree\.parse\s*\('),
        "description": "Using xml.etree.ElementTree.parse without disabling external entity processing can lead to XXE attacks.",
        "recommendation": "Use defusedxml library instead of xml.etree.ElementTree to prevent XXE attacks."
    },
    {
        "name": "Insecure XML Parsing (xml.dom.minidom)",
        "pattern": re.compile(r'xml\.dom\.minidom\.parse\s*\('),
        "description": "Using xml.dom.minidom.parse without precautions can allow XXE attacks.",
        "recommendation": "Use defusedxml.minidom instead of xml.dom.minidom for safe XML parsing."
    },
    {
        "name": "Insecure XML Parsing (xml.sax)",
        "pattern": re.compile(r'xml\.sax\.make_parser\s*\(\)'),
        "description": "Using xml.sax.make_parser without proper security settings can lead to XXE vulnerabilities.",
        "recommendation": "Use defusedxml.sax instead of xml.sax to mitigate XXE risks."
    },
    {
        "name": "Insecure XML Parsing (lxml)",
        "pattern": re.compile(r'lxml\.etree\.parse\s*\('),
        "description": "Using lxml.etree.parse can allow XXE attacks if not properly configured.",
        "recommendation": "Disable external entity loading in lxml or use defusedxml."
    }
]

def scan_for_xxe_vulnerabilities(directory):
    """Scans Python files for XML parser vulnerabilities."""
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
                    for vuln in XXE_VULNERABILITIES:
                        if vuln["pattern"].search(line):
                            results.append({
                                "Vulnerability": vuln["name"],
                                "Line Number": line_no,
                                "File Path": file_path,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })

    return results

def export_results_to_csv_excel(results, output_folder):
    """Exports scan results to CSV and Excel files."""
    if not results:
        print("\n✅ No XXE vulnerabilities found!")
        return

    df = pd.DataFrame(results)
    
    csv_path = os.path.join(output_folder, "xxe_vulnerabilities_report.csv")
    excel_path = os.path.join(output_folder, "xxe_vulnerabilities_report.xlsx")
    
    df.to_csv(csv_path, index=False)
    df.to_excel(excel_path, index=False)

    print(f"\n📂 Results saved to:\n  - {csv_path}\n  - {excel_path}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for XXE vulnerabilities...")
    vulnerabilities_found = scan_for_xxe_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Potential XXE Vulnerabilities Found:")
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
