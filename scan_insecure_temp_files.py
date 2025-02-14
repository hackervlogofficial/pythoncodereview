import os
import re
import csv
import pandas as pd

# Define patterns for detecting insecure temporary file creation
INSECURE_TEMP_FILE_PATTERNS = [
    {
        "name": "Use of tempfile.mktemp()",
        "pattern": re.compile(r'tempfile\.mktemp\s*\(\s*\)', re.IGNORECASE),
        "description": "Using `tempfile.mktemp()` is insecure because it creates a race condition.",
        "recommendation": "Use `tempfile.NamedTemporaryFile(delete=True)` or `tempfile.TemporaryFile()` instead."
    },
    {
        "name": "Insecure /tmp/ File Creation",
        "pattern": re.compile(r'open\s*\(\s*["\']/tmp/[^"\']*["\']', re.IGNORECASE),
        "description": "Creating files directly in `/tmp/` can be exploited by attackers.",
        "recommendation": "Use `tempfile.NamedTemporaryFile()` or `tempfile.TemporaryFile()` instead."
    },
    {
        "name": "Use of os.system() with Temporary Files",
        "pattern": re.compile(r'os\.system\s*\(.*"/tmp/.*"\)', re.IGNORECASE),
        "description": "Executing system commands with temporary files in `/tmp/` can be exploited by attackers.",
        "recommendation": "Use `subprocess.run()` with securely created temporary files instead."
    },
    {
        "name": "Use of os.popen() with Temporary Files",
        "pattern": re.compile(r'os\.popen\s*\(.*"/tmp/.*"\)', re.IGNORECASE),
        "description": "Using `os.popen()` with temporary files in `/tmp/` can lead to command injection vulnerabilities.",
        "recommendation": "Use `subprocess.Popen()` with securely created temporary files instead."
    }
]

def scan_for_insecure_temp_files(directory):
    """Scans Python files for insecure temporary file creation methods and returns detailed reports."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in INSECURE_TEMP_FILE_PATTERNS:
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

def save_results_csv(results, filename="vulnerability_scan_results.csv"):
    """Saves results to a CSV file."""
    keys = results[0].keys() if results else []
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)
    print(f"Results saved to {filename}")

def save_results_excel(results, filename="vulnerability_scan_results.xlsx"):
    """Saves results to an Excel file."""
    df = pd.DataFrame(results)
    df.to_excel(filename, index=False)
    print(f"Results saved to {filename}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\nScanning for insecure temporary file usage...")
    vulnerabilities_found = scan_for_insecure_temp_files(folder_to_scan)

    if vulnerabilities_found:
        print("\n🔴 Potential Insecure Temporary File Issues Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)
        
        # Save results
        save_results_csv(vulnerabilities_found)
        save_results_excel(vulnerabilities_found)
    else:
        print("✅ No insecure temporary file usage vulnerabilities found!")

if __name__ == "__main__":
    main()
