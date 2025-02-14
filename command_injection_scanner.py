import os
import re
import pandas as pd

# Define patterns for insecure OS command execution
COMMAND_INJECTION_PATTERNS = [
    {
        "name": "Command Injection via os.system",
        "pattern": re.compile(r'os\.system\s*\(.*\)'),
        "description": "Using os.system() with unsanitized user input can lead to command injection.",
        "recommendation": "Use subprocess.run() with a list instead of os.system(). Validate and sanitize input before execution."
    },
    {
        "name": "Command Injection via subprocess.Popen",
        "pattern": re.compile(r'subprocess\.Popen\s*\(.*\)'),
        "description": "Using subprocess.Popen() with untrusted input can allow attackers to execute arbitrary commands.",
        "recommendation": "Use subprocess.run() with shell=False and pass arguments as a list to prevent shell injection."
    },
    {
        "name": "Command Injection via subprocess.call",
        "pattern": re.compile(r'subprocess\.call\s*\(.*\)'),
        "description": "Using subprocess.call() with shell=True can allow command injection if input is not sanitized.",
        "recommendation": "Use subprocess.run() with shell=False and validate input to prevent command injection."
    },
    {
        "name": "Command Injection via eval",
        "pattern": re.compile(r'eval\s*\(.*\)'),
        "description": "Using eval() with untrusted input allows arbitrary code execution, which is a severe security risk.",
        "recommendation": "Avoid using eval(). Use safer alternatives like ast.literal_eval() for evaluating expressions."
    },
    {
        "name": "Command Injection via exec",
        "pattern": re.compile(r'exec\s*\(.*\)'),
        "description": "Using exec() with unsanitized user input can allow attackers to execute arbitrary Python code.",
        "recommendation": "Avoid using exec(). Use safer alternatives or strictly validate input before execution."
    }
]

def scan_for_command_injection(directory):
    """Scans Python files for OS command injection vulnerabilities."""
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
                    for vuln in COMMAND_INJECTION_PATTERNS:
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
        print("\n✅ No OS Command Injection vulnerabilities found!")
        return

    df = pd.DataFrame(results)
    
    csv_path = os.path.join(output_folder, "command_injection_report.csv")
    excel_path = os.path.join(output_folder, "command_injection_report.xlsx")
    
    df.to_csv(csv_path, index=False)
    df.to_excel(excel_path, index=False)

    print(f"\n📂 Results saved to:\n  - {csv_path}\n  - {excel_path}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for OS Command Injection vulnerabilities...")
    vulnerabilities_found = scan_for_command_injection(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Potential OS Command Injection Vulnerabilities Found:")
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
