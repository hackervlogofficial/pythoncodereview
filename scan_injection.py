import os
import re
import pandas as pd

# Define patterns and details for injection vulnerabilities
INJECTION_VULNERABILITIES = [
    {
        "name": "Eval Injection",
        "pattern": re.compile(r"eval\s*\((.*)\)"),
        "description": "Using eval() can lead to remote code execution if untrusted input is processed.",
        "recommendation": "Avoid using eval(). Instead, use safer alternatives like ast.literal_eval() for parsing safe inputs."
    },
    {
        "name": "Exec Injection",
        "pattern": re.compile(r"exec\s*\((.*)\)"),
        "description": "The exec() function allows execution of arbitrary Python code, making it dangerous.",
        "recommendation": "Avoid using exec(). If needed, use safer alternatives such as dictionary-based execution."
    },
    {
        "name": "OS Command Injection",
        "pattern": re.compile(r'os\.system\s*\((.*)\)'),
        "description": "Using os.system() with user input can allow command injection attacks.",
        "recommendation": "Use subprocess.run() with a list format to avoid shell injection vulnerabilities."
    },
    {
        "name": "Subprocess Command Injection",
        "pattern": re.compile(r'subprocess\.(run|Popen|call|check_output)\s*\((.*)\)'),
        "description": "Executing shell commands directly can be dangerous if inputs are not sanitized.",
        "recommendation": "Use subprocess.run() with shell=False and proper input validation to prevent injection."
    }
]

def scan_for_injection(directory):
    """Scans Python files in the directory for injection vulnerabilities and returns detailed reports."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                
                for line_no, line in enumerate(lines, start=1):
                    for vuln in INJECTION_VULNERABILITIES:
                        match = vuln["pattern"].search(line)
                        if match:
                            results.append({
                                "Vulnerability": vuln["name"],
                                "File Path": file_path,
                                "Line No": line_no,
                                "Vulnerable Code": line.strip(),
                                "Description": vuln["description"],
                                "Recommendation": vuln["recommendation"]
                            })
    
    return results

def export_results(results, output_dir):
    """Exports the results to CSV and Excel formats."""
    if not results:
        print("✅ No vulnerabilities found. No export performed.")
        return
    
    df = pd.DataFrame(results)
    
    csv_file = os.path.join(output_dir, "scan_results.csv")
    excel_file = os.path.join(output_dir, "scan_results.xlsx")
    
    df.to_csv(csv_file, index=False)
    df.to_excel(excel_file, index=False, engine="openpyxl")

    print(f"\n📂 Results exported to:\n  - {csv_file}\n  - {excel_file}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()
    
    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return
    
    print("\n🔍 Scanning for injection vulnerabilities...")
    vulnerabilities_found = scan_for_injection(folder_to_scan)
    
    if vulnerabilities_found:
        print("\n🔴 Potential Injection Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)
        
        # Export results
        export_results(vulnerabilities_found, folder_to_scan)
    else:
        print("✅ No injection vulnerabilities found!")

if __name__ == "__main__":
    main()
