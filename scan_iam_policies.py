import os
import re
import json
import csv
import pandas as pd

# Define patterns to detect insecure IAM policies in Python source code
IAM_VULNERABILITY_PATTERNS = [
    {
        "name": "Overly Permissive IAM Action",
        "pattern": re.compile(r'"Action"\s*:\s*\["\*"]', re.IGNORECASE),
        "description": "IAM policy grants all actions, which is overly permissive.",
        "recommendation": "Restrict 'Action' to specific AWS services and operations instead of '*'."
    },
    {
        "name": "Overly Permissive IAM Resource",
        "pattern": re.compile(r'"Resource"\s*:\s*\["\*"]', re.IGNORECASE),
        "description": "IAM policy grants access to all AWS resources, which is a security risk.",
        "recommendation": "Restrict 'Resource' to specific AWS resource ARNs instead of '*'."
    }
]

def scan_for_iam_vulnerabilities(directory):
    """Scans Python files for insecure AWS IAM policies."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in IAM_VULNERABILITY_PATTERNS:
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

def export_results_csv(results, output_file="iam_vulnerabilities.csv"):
    """Exports scan results to a CSV file."""
    if results:
        keys = results[0].keys()
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        print(f"📂 Results saved to {output_file}")
    else:
        print("✅ No vulnerabilities found. No CSV generated.")

def export_results_excel(results, output_file="iam_vulnerabilities.xlsx"):
    """Exports scan results to an Excel file."""
    if results:
        df = pd.DataFrame(results)
        df.to_excel(output_file, index=False)
        print(f"📂 Results saved to {output_file}")
    else:
        print("✅ No vulnerabilities found. No Excel file generated.")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for insecure AWS IAM policies...")
    vulnerabilities_found = scan_for_iam_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Insecure AWS IAM Policies Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)
    else:
        print("✅ No insecure AWS IAM policies found!")

    # Export results
    export_results_csv(vulnerabilities_found)
    export_results_excel(vulnerabilities_found)

if __name__ == "__main__":
    main()