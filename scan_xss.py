import os
import re
import pandas as pd

# Define patterns for detecting possible XSS vulnerabilities
XSS_VULNERABILITIES = [
    {
        "name": "Unescaped User Input in Web Response",
        "pattern": re.compile(r'return\s+["\']?\s*\w*\s*\+\s*request\.(args|get|form|values|json).*', re.IGNORECASE),
        "description": "User input is directly reflected in the response without sanitization.",
        "recommendation": "Use Flask's escape() function or sanitize input before rendering it."
    },
    {
        "name": "Use of Jinja2 autoescape=False",
        "pattern": re.compile(r'autoescape\s*=\s*False', re.IGNORECASE),
        "description": "Disabling autoescape in Jinja2 templates makes the application vulnerable to XSS.",
        "recommendation": "Ensure that Jinja2 templates use autoescape=True by default."
    },
    {
        "name": "Direct Injection of User Input into HTML",
        "pattern": re.compile(r'render_template_string\s*\(.*request\.(args|get|form|values|json)', re.IGNORECASE),
        "description": "User input is being directly injected into an HTML template, which can lead to XSS.",
        "recommendation": "Use render_template instead of render_template_string to ensure proper escaping."
    },
    {
        "name": "Unsafe JavaScript Code Execution",
        "pattern": re.compile(r'exec\(\s*request\.(args|get|form|values|json)', re.IGNORECASE),
        "description": "User input is being executed as code, which is highly dangerous and allows XSS.",
        "recommendation": "Avoid using exec() with user input. Instead, use safe alternatives like predefined mappings."
    }
]

def scan_for_xss(directory):
    """Scans Python files in the directory for XSS vulnerabilities and returns detailed reports."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in XSS_VULNERABILITIES:
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

def export_results(vulnerabilities):
    """Exports the vulnerabilities to both Excel and CSV formats using openpyxl for Excel."""
    if not vulnerabilities:
        print("No vulnerabilities found. Skipping export.")
        return

    df = pd.DataFrame(vulnerabilities)

    # Export to CSV
    csv_filename = "xss_vulnerabilities.csv"
    df.to_csv(csv_filename, index=False)
    print(f"✅ Results exported to {csv_filename}")

    # Export to Excel using openpyxl
    excel_filename = "xss_vulnerabilities.xlsx"
    df.to_excel(excel_filename, index=False, engine="openpyxl")
    print(f"✅ Results exported to {excel_filename}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\nScanning for XSS vulnerabilities...")
    vulnerabilities_found = scan_for_xss(folder_to_scan)

    if vulnerabilities_found:
        print("\n🔴 Potential XSS Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['vulnerability']}")
            print(f"📍 Location: {vuln['file_path']} (Line {vuln['line_no']})")
            print(f"📝 Description: {vuln['description']}")
            print(f"⚠️ Vulnerable Code: {vuln['vulnerable_code']}")
            print(f"✅ Recommendation: {vuln['recommendation']}")
            print("-" * 80)

        # Export results to Excel and CSV
        export_results(vulnerabilities_found)
    else:
        print("✅ No XSS vulnerabilities found!")

if __name__ == "__main__":
    main()
