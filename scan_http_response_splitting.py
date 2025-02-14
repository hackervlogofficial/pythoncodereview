import os
import re
import csv
import pandas as pd

# Define patterns to detect potential HTTP Response Splitting vulnerabilities
VULNERABILITY_PATTERNS = [
    {
        "name": "Potential HTTP Response Splitting via response header",
        "pattern": re.compile(r'response\.headers\s*\[\s*["\'][^"\']*["\']\s*\]\s*=\s*.*\binput\b', re.IGNORECASE),
        "description": "User-controlled input in response headers may allow response splitting attacks.",
        "recommendation": "Sanitize input by removing CRLF characters before adding it to headers."
    },
    {
        "name": "Potential HTTP Response Splitting via response.set_cookie()",
        "pattern": re.compile(r'response\.set_cookie\s*\(\s*[^,]+,\s*\binput\b', re.IGNORECASE),
        "description": "Unvalidated user input in response.set_cookie() may allow response splitting attacks.",
        "recommendation": "Ensure cookie values do not contain newline characters (`\\r` or `\\n`)."
    },
    {
        "name": "Potential Response Splitting via string concatenation",
        "pattern": re.compile(r'header\s*\+=\s*\binput\b', re.IGNORECASE),
        "description": "Directly appending user input to HTTP headers may allow response splitting.",
        "recommendation": "Validate and encode input to prevent header injection."
    }
]

def scan_for_vulnerabilities(directory):
    """Scans Python files for HTTP Response Splitting vulnerabilities."""
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
                                "vulnerability": vuln["name"],
                                "line_no": line_no,
                                "file_path": file_path,
                                "description": vuln["description"],
                                "vulnerable_code": line.strip(),
                                "recommendation": vuln["recommendation"]
                            })

    return results

def export_results_csv(results, output_file="response_splitting_scan_results.csv"):
    """Exports results to a CSV file."""
    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"📄 Results saved to {output_file}")

def export_results_excel(results, output_file="response_splitting_scan_results.xlsx"):
    """Exports results to an Excel file."""
    df = pd.DataFrame(results)
    df.to_excel(output_file, index=False)
    print(f"📄 Results saved to {output_file}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\nScanning for HTTP Response Splitting vulnerabilities...")
    vulnerabilities_found = scan_for_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🔴 Potential HTTP Response Splitting Issues Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['vulnerability']}")
            print(f"📍 Location: {vuln['file_path']} (Line {vuln['line_no']})")
            print(f"📝 Description: {vuln['description']}")
            print(f"⚠️ Vulnerable Code: {vuln['vulnerable_code']}")
            print(f"✅ Recommendation: {vuln['recommendation']}")
            print("-" * 80)

        # Export results
        export_results_csv(vulnerabilities_found)
        export_results_excel(vulnerabilities_found)
    else:
        print("✅ No HTTP Response Splitting vulnerabilities found!")

if __name__ == "__main__":
    main()
