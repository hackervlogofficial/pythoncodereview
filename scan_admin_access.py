import os
import re
import csv
import pandas as pd

# Define patterns to detect unrestricted admin access vulnerabilities
VULNERABILITY_PATTERNS = [
    {
        "name": "Unrestricted Flask Admin Access",
        "pattern": re.compile(r'@app.route\(["\']/admin["\'].*\)', re.IGNORECASE),
        "description": "Admin routes should be restricted to specific IPs.",
        "recommendation": "Implement IP-based restrictions in Flask before allowing access."
    },
    {
        "name": "Unrestricted Django Admin Access",
        "pattern": re.compile(r'path\(["\']admin\/\["\'],', re.IGNORECASE),
        "description": "Django's admin panel should be restricted to specific IP addresses.",
        "recommendation": "Use Django's ALLOWED_HOSTS or middleware for IP-based restrictions."
    },
    {
        "name": "Unrestricted IP Binding",
        "pattern": re.compile(r'host\s*=\s*["\']0\.0\.0\.0["\']', re.IGNORECASE),
        "description": "Binding to 0.0.0.0 exposes the service to all networks.",
        "recommendation": "Restrict the binding address to a trusted IP range (e.g., 127.0.0.1 or internal network IP)."
    },
    {
        "name": "Lack of IP Restriction in Flask Middleware",
        "pattern": re.compile(r'request.remote_addr', re.IGNORECASE),
        "description": "Admin route should validate request.remote_addr to restrict IP access.",
        "recommendation": "Check request.remote_addr in a middleware or decorator to allow only trusted IPs."
    }
]

def scan_for_vulnerabilities(directory):
    """Scans Python files for admin access security issues."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in VULNERABILITY_PATTERNS:
                        if vuln["pattern"].search(line):
                            results.append({
                                "Vulnerability": vuln["name"],
                                "Line No": line_no,
                                "File Path": file_path,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })
    return results

def save_results_to_csv(results, output_file):
    """Saves scan results to a CSV file."""
    keys = results[0].keys() if results else []
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

def save_results_to_excel(results, output_file):
    """Saves scan results to an Excel file."""
    if results:
        df = pd.DataFrame(results)
        df.to_excel(output_file, index=False)

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for unrestricted admin access vulnerabilities...")
    vulnerabilities_found = scan_for_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Unrestricted Admin Access Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)
        
        # Save results to CSV and Excel
        csv_file = "vulnerability_scan_results.csv"
        excel_file = "vulnerability_scan_results.xlsx"
        save_results_to_csv(vulnerabilities_found, csv_file)
        save_results_to_excel(vulnerabilities_found, excel_file)
        print(f"\n📂 Results saved to {csv_file} and {excel_file}")
    else:
        print("✅ No unrestricted admin access vulnerabilities found!")

if __name__ == "__main__":
    main()