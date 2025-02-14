import os
import re
import csv
import pandas as pd

# Define regex patterns to identify exposed stack traces
VULNERABILITY_PATTERNS = [
    {
        "name": "Stack Trace Disclosure",
        "pattern": re.compile(
            r'(traceback\.format_exc\(\)|traceback\.print_exc\(\)|sys\.exc_info\(\)|'
            r'traceback\.extract_tb\(\)|traceback\.extract_stack\(\)|traceback\.format_tb\(\)|'
            r'traceback\.format_stack\(\)|traceback\.walk_stack\(\))',
            re.IGNORECASE,
        ),
        "description": "Exposed stack traces may reveal sensitive system details, such as file paths and internal functions, which attackers can exploit.",
        "recommendation": "Log errors securely without exposing stack traces. Use structured logging and generic error messages (e.g., `logging.error('An error occurred')`)."
    }
]

def scan_for_vulnerabilities(directory):
    """Scans Python files for stack trace disclosure vulnerabilities."""
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
    csv_file = os.path.join(output_dir, "stack_trace_disclosures.csv")

    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\n📁 CSV Report saved: {csv_file}")

def save_to_excel(results, output_dir):
    """Saves scan results to an Excel file."""
    os.makedirs(output_dir, exist_ok=True)
    excel_file = os.path.join(output_dir, "stack_trace_disclosures.xlsx")

    df = pd.DataFrame(results)
    df.to_excel(excel_file, index=False)

    print(f"📁 Excel Report saved: {excel_file}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for stack trace disclosures...")
    vulnerabilities_found = scan_for_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Stack Trace Disclosure Found:")
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
        print("✅ No stack trace disclosure found!")

if __name__ == "__main__":
    main()
