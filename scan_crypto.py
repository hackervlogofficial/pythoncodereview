import os
import re
import pandas as pd
from datetime import datetime

# Define patterns and details for weak cryptographic vulnerabilities
CRYPTO_VULNERABILITIES = [
    {
        "name": "Weak Hashing Algorithm (MD5)",
        "pattern": re.compile(r'hashlib\.md5\s*\(.*\)'),
        "description": "MD5 is a weak hashing algorithm and is vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 or SHA-3 instead of MD5."
    },
    {
        "name": "Weak Hashing Algorithm (SHA1)",
        "pattern": re.compile(r'hashlib\.sha1\s*\(.*\)'),
        "description": "SHA-1 is weak and vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 or SHA-3 for better security."
    },
    {
        "name": "Hardcoded Cryptographic Key",
        "pattern": re.compile(r'("|\')?[A-Za-z0-9+/=]{16,64}("|\')'),
        "description": "Hardcoded cryptographic keys can be extracted by attackers.",
        "recommendation": "Store cryptographic keys securely in environment variables or a secrets manager."
    },
    {
        "name": "Insecure Encryption Mode (ECB)",
        "pattern": re.compile(r'AES\.new\s*\(.*,\s*AES\.ECB'),
        "description": "ECB mode encryption is insecure as it reveals patterns in encrypted data.",
        "recommendation": "Use CBC or GCM mode instead of ECB for better security."
    },
    {
        "name": "Weak Random Number Generator (random.random)",
        "pattern": re.compile(r'random\.random\s*\(\)'),
        "description": "random.random() is not cryptographically secure and should not be used for security-sensitive applications.",
        "recommendation": "Use secrets module (secrets.token_bytes, secrets.randbelow) for cryptographic operations."
    }
]

def scan_for_crypto_issues(directory):
    """Scans Python files in the directory for cryptographic weaknesses and returns detailed reports."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                
                for line_no, line in enumerate(lines, start=1):
                    for vuln in CRYPTO_VULNERABILITIES:
                        match = vuln["pattern"].search(line)
                        if match:
                            results.append({
                                "Vulnerability": vuln["name"],
                                "File Path": file_path,
                                "Line No": line_no,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })
    
    return results

def export_results(results):
    """Exports results to CSV and Excel format with a timestamp."""
    if not results:
        print("✅ No vulnerabilities found. No export required.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"crypto_vulnerabilities_{timestamp}.csv"
    excel_filename = f"crypto_vulnerabilities_{timestamp}.xlsx"

    df = pd.DataFrame(results)

    # Export to CSV
    df.to_csv(csv_filename, index=False, encoding="utf-8")
    
    # Export to Excel using openpyxl
    try:
        df.to_excel(excel_filename, index=False, engine="openpyxl")
    except ModuleNotFoundError:
        print("\n⚠️ 'openpyxl' module is missing! Installing it now...")
        os.system("pip install openpyxl")
        df.to_excel(excel_filename, index=False, engine="openpyxl")

    print(f"\n✅ Results exported successfully!")
    print(f"📂 CSV File: {csv_filename}")
    print(f"📂 Excel File: {excel_filename}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()
    
    if not os.path.exists(folder_to_scan):
        print("Invalid folder path! Please enter a valid path.")
        return
    
    print("\n🔍 Scanning for cryptographic vulnerabilities...")
    vulnerabilities_found = scan_for_crypto_issues(folder_to_scan)
    
    if vulnerabilities_found:
        print("\n🔴 Potential Cryptographic Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)
    else:
        print("✅ No cryptographic vulnerabilities found!")

    # Export results to CSV and Excel
    export_results(vulnerabilities_found)

if __name__ == "__main__":
    main()
