import os
import re
import csv
import pandas as pd

# Define regex patterns to identify vulnerable memory allocation
VULNERABILITY_PATTERNS = [
    {
        "name": "Memory Allocation DoS",
        "pattern": re.compile(r'\w+\s*=\s*\[\s*0\s*\]\s*\*\s*[a-zA-Z_]+', re.IGNORECASE),
        "description": "Unvalidated user input controlling memory allocation size can cause Denial of Service (DoS) by consuming excessive memory.",
        "recommendation": "Sanitize and limit user-controlled values before using them in memory allocations."
    },
    {
        "name": "Memory Allocation DoS",
        "pattern": re.compile(r'bytearray\(\s*[a-zA-Z_]+\s*\)', re.IGNORECASE),
        "description": "User-controlled input defining memory allocation size can lead to excessive memory consumption.",
        "recommendation": "Restrict maximum allocation size and validate user input."
    },
    {
        "name": "Memory Allocation DoS",
        "pattern": re.compile(r'bytes\(\s*[a-zA-Z_]+\s*\)', re.IGNORECASE),
        "description": "User input controlling byte allocation can cause excessive memory usage.",
        "recommendation": "Enforce strict limits on maximum memory allocation size."
    },
    {
        "name": "Memory Allocation DoS",
        "pattern": re.compile(r'list\(\)\s*\*\s*[a-zA-Z_]+', re.IGNORECASE),
        "description": "Dynamic list allocation based on user input can lead to uncontrolled memory usage.",
        "recommendation": "Ensure user input is validated and impose reasonable size limits."
    }
]

def scan_for_vulnerabilities(directory):
    """Scans Python files for memory allocation DoS vulnerabilities."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in VULNERABILITY_PATTERNS:
                        match = vuln["pattern"].search(line)
                        if match:
                            results.append({
                                "Vulnerability": vuln["name"],
                                "File Path": file_path,
                                "Line No.": line_no,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })

    return results

def save_to_csv(results, output_dir):
    """Saves scan results to a CSV file."""
    os.makedirs(output_dir, exist_ok=True)
    csv_file = os.path.join(output_dir, "memory_allocation_vulnerabilities.csv")

    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\n📁 CSV Report saved: {csv_file}")

def save_to_excel(results, output_dir):
    """Saves scan results to an Excel file."""
    os.makedirs(output_dir, exist_ok=True)
    excel_file = os.path.join(output_dir, "memory_allocation_vulnerabilities.xlsx")

    df = pd.DataFrame(results)
    df.to_excel(excel_file, index=False)

    print(f"📁 Excel Report saved: {excel_file}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for memory allocation DoS vulnerabilities...")
    vulnerabilities_found = scan_for_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Memory Allocation DoS Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No.']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)

        # Save results to CSV and Excel
        output_dir = "output"
        save_to_csv(vulnerabilities_found, output_dir)
        save_to_excel(vulnerabilities_found, output_dir)
    else:
        print("✅ No memory allocation DoS vulnerabilities found!")

if __name__ == "__main__":
    main()
