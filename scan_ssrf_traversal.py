import os
import re
import csv
import pandas as pd

# Define patterns for detecting SSRF and Path Traversal vulnerabilities
VULNERABILITY_PATTERNS = [
    {
        "name": "Potential SSRF via requests.get()",
        "pattern": re.compile(r'requests\.get\s*\(\s*[^)]*\)', re.IGNORECASE),
        "description": "Unvalidated user input used in requests.get() can lead to SSRF attacks.",
        "recommendation": "Validate input and restrict external access using allowlist filtering."
    },
    {
        "name": "Potential SSRF via urllib",
        "pattern": re.compile(r'urllib\.request\.urlopen\s*\(\s*[^)]*\)', re.IGNORECASE),
        "description": "Unvalidated user input used in urllib.request.urlopen() can lead to SSRF attacks.",
        "recommendation": "Use allowlisted URLs and avoid dynamic input from users."
    },
    {
        "name": "Potential Path Traversal via open()",
        "pattern": re.compile(r'open\s*\(\s*[a-zA-Z_]*\s*\+\s*[a-zA-Z_]*', re.IGNORECASE),
        "description": "Concatenating user input with file paths in open() can allow directory traversal.",
        "recommendation": "Sanitize input and restrict file access to specific directories."
    },
    {
        "name": "Potential Path Traversal via os.path.join()",
        "pattern": re.compile(r'os\.path\.join\s*\(\s*[^)]*\)', re.IGNORECASE),
        "description": "User-controlled input in os.path.join() may lead to directory traversal attacks.",
        "recommendation": "Ensure user input is sanitized and use absolute paths."
    },
    {
        "name": "Potential Unsafe File Operations with shutil",
        "pattern": re.compile(r'shutil\.[a-zA-Z_]+\s*\(\s*[^)]*\)', re.IGNORECASE),
        "description": "Unvalidated user input in shutil functions may allow arbitrary file operations.",
        "recommendation": "Restrict input to predefined directories and validate file paths."
    }
]

def scan_for_vulnerabilities(directory):
    """Scans Python files for SSRF and Path Traversal vulnerabilities."""
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

def export_results_csv(results, output_file="vulnerability_scan_results.csv"):
    """Exports results to a CSV file."""
    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"📄 Results saved to {output_file}")

def export_results_excel(results, output_file="vulnerability_scan_results.xlsx"):
    """Exports results to an Excel file."""
    df = pd.DataFrame(results)
    df.to_excel(output_file, index=False)
    print(f"📄 Results saved to {output_file}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\nScanning for SSRF and Path Traversal vulnerabilities...")
    vulnerabilities_found = scan_for_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🔴 Potential SSRF and Path Traversal Issues Found:")
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
        print("✅ No SSRF or Path Traversal vulnerabilities found!")

if __name__ == "__main__":
    main()
