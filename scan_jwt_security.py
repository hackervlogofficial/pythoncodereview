import os
import re
import csv
import pandas as pd

# Define patterns to detect insecure JWT usage
JWT_VULNERABILITY_PATTERNS = [
    {
        "name": "JWT Created Without Signing",
        "pattern": re.compile(r'jwt\.encode\s*\(.*,\s*None', re.IGNORECASE),
        "description": "JWTs should always be signed with a secret or private key to prevent tampering.",
        "recommendation": "Use a strong secret key when encoding JWTs."
    },
    {
        "name": "JWT Decoded Without Verification",
        "pattern": re.compile(r'jwt\.decode\s*\(.*,\s*options\s*=\s*\{.*\"verify_signature\":\s*False.*\}', re.IGNORECASE),
        "description": "Decoding JWTs without verifying the signature allows attackers to forge tokens.",
        "recommendation": "Always verify the JWT signature using a secret or public key."
    },
    {
        "name": "JWT Decoded Without Providing a Key",
        "pattern": re.compile(r'jwt\.decode\s*\(\s*[^,]+,\s*None', re.IGNORECASE),
        "description": "JWTs should not be decoded without a secret or public key, as this allows unauthenticated tokens.",
        "recommendation": "Provide a valid secret or public key when decoding JWTs."
    }
]

def scan_for_jwt_issues(directory):
    """Scans Python files for insecure JWT handling."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in JWT_VULNERABILITY_PATTERNS:
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

def export_to_csv(results, output_file="jwt_scan_results.csv"):
    """Exports scan results to a CSV file."""
    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"📄 Results exported to CSV: {output_file}")

def export_to_excel(results, output_file="jwt_scan_results.xlsx"):
    """Exports scan results to an Excel file."""
    df = pd.DataFrame(results)
    df.to_excel(output_file, index=False)
    print(f"📊 Results exported to Excel: {output_file}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for insecure JWT usage...")
    vulnerabilities_found = scan_for_jwt_issues(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Insecure JWT Usage Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)

        # Export results to CSV and Excel
        export_to_csv(vulnerabilities_found)
        export_to_excel(vulnerabilities_found)
    else:
        print("✅ No insecure JWT usage found!")

if __name__ == "__main__":
    main()
