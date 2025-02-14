import os
import re
import csv
import pandas as pd

# Define patterns for detecting insecure deserialization vulnerabilities
DESERIALIZATION_VULNERABILITIES = [
    {
        "name": "Insecure use of pickle.load()",
        "pattern": re.compile(r'pickle\.load\s*\(\s*\w*\s*\)', re.IGNORECASE),
        "description": "Using pickle.load() on untrusted input can lead to remote code execution.",
        "recommendation": "Use safer alternatives like json.load() if possible, or restrict input to trusted sources."
    },
    {
        "name": "Insecure use of pickle.loads()",
        "pattern": re.compile(r'pickle\.loads\s*\(\s*\w*\s*\)', re.IGNORECASE),
        "description": "Using pickle.loads() on untrusted input can execute arbitrary code.",
        "recommendation": "Use json.loads() instead of pickle for handling untrusted data."
    },
    {
        "name": "Insecure use of marshal.load()",
        "pattern": re.compile(r'marshal\.load\s*\(\s*\w*\s*\)', re.IGNORECASE),
        "description": "Using marshal.load() can allow execution of arbitrary bytecode.",
        "recommendation": "Avoid using marshal for untrusted data; use safer serialization formats like JSON."
    },
    {
        "name": "Insecure use of marshal.loads()",
        "pattern": re.compile(r'marshal\.loads\s*\(\s*\w*\s*\)', re.IGNORECASE),
        "description": "Using marshal.loads() can execute arbitrary code.",
        "recommendation": "Marshal should not be used for untrusted data. Consider safer alternatives."
    },
    {
        "name": "Insecure use of eval() for deserialization",
        "pattern": re.compile(r'eval\s*\(\s*\w*\s*\)', re.IGNORECASE),
        "description": "Using eval() on untrusted data can lead to code execution vulnerabilities.",
        "recommendation": "Use safer alternatives like ast.literal_eval() if parsing structured data."
    }
]

def scan_for_insecure_deserialization(directory):
    """Scans Python files for insecure deserialization vulnerabilities and returns detailed reports."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in DESERIALIZATION_VULNERABILITIES:
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

def export_results(results, output_folder):
    """Exports the results to CSV and Excel."""
    if not results:
        print("No vulnerabilities to export.")
        return

    os.makedirs(output_folder, exist_ok=True)
    csv_filename = os.path.join(output_folder, "insecure_deserialization_results.csv")
    excel_filename = os.path.join(output_folder, "insecure_deserialization_results.xlsx")

    # Export to CSV
    with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = results[0].keys()
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"Results exported to CSV: {csv_filename}")

    # Export to Excel using openpyxl
    df = pd.DataFrame(results)
    df.to_excel(excel_filename, index=False, engine="openpyxl")
    print(f"Results exported to Excel: {excel_filename}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()
    output_folder = "scan_results"

    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\nScanning for insecure deserialization vulnerabilities...")
    vulnerabilities_found = scan_for_insecure_deserialization(folder_to_scan)

    if vulnerabilities_found:
        print("\n🔴 Potential Insecure Deserialization Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)

        # Export results
        export_results(vulnerabilities_found, output_folder)
    else:
        print("✅ No insecure deserialization vulnerabilities found!")

if __name__ == "__main__":
    main()
