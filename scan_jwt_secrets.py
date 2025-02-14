import os
import re
import csv
import pandas as pd

# Define regex patterns to identify hardcoded JWT secrets in Python, JSON, and ENV files
VULNERABILITY_PATTERNS = [
    {
        "name": "Hardcoded JWT Secret Key",
        "pattern": re.compile(r'(["\']?)?(JWT_SECRET|SECRET_KEY|JWT_SECRET_KEY|SECRET|PRIVATE_KEY)(["\'])?\s*=\s*(["\'])(.{8,})(\4)', re.IGNORECASE),
        "description": "Hardcoded JWT secret keys make applications vulnerable to token forgery and security breaches.",
        "recommendation": "Store secrets securely using environment variables or secret management tools (e.g., AWS Secrets Manager, HashiCorp Vault)."
    }
]

def scan_for_vulnerabilities(directory):
    """Scans Python, JSON, and ENV files for exposed JWT secret keys."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".py", ".json", ".env")):
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
    csv_file = os.path.join(output_dir, "jwt_vulnerabilities.csv")

    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\n📁 CSV Report saved: {csv_file}")

def save_to_excel(results, output_dir):
    """Saves scan results to an Excel file."""
    excel_file = os.path.join(output_dir, "jwt_vulnerabilities.xlsx")

    df = pd.DataFrame(results)
    df.to_excel(excel_file, index=False)

    print(f"📁 Excel Report saved: {excel_file}")

def main():
    folder_to_scan = input("Enter the folder path containing source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for hardcoded JWT secrets...")
    vulnerabilities_found = scan_for_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Hardcoded JWT Secrets Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No.']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)

        # Create output directory if it doesn't exist
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)

        # Export results
        save_to_csv(vulnerabilities_found, output_dir)
        save_to_excel(vulnerabilities_found, output_dir)

    else:
        print("✅ No exposed JWT secret keys found!")

if __name__ == "__main__":
    main()
