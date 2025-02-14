import os
import re
import csv
import pandas as pd

# Define patterns to detect weak cipher algorithms
WEAK_CIPHER_PATTERNS = [
    {
        "name": "Use of Weak Hash Algorithm (MD5)",
        "pattern": re.compile(r'hashlib\.md5\s*\(', re.IGNORECASE),
        "description": "MD5 is a weak hash function and is vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 or SHA-512 instead."
    },
    {
        "name": "Use of Weak Hash Algorithm (SHA1)",
        "pattern": re.compile(r'hashlib\.sha1\s*\(', re.IGNORECASE),
        "description": "SHA1 is considered weak and vulnerable to attacks.",
        "recommendation": "Use SHA-256 or SHA-512 instead."
    },
    {
        "name": "Use of Weak Encryption Algorithm (DES)",
        "pattern": re.compile(r'Crypto\.Cipher\.DES\s*\(', re.IGNORECASE),
        "description": "DES is outdated and vulnerable to brute-force attacks.",
        "recommendation": "Use AES-256 with GCM mode instead."
    },
    {
        "name": "Use of Weak Encryption Algorithm (Blowfish)",
        "pattern": re.compile(r'Crypto\.Cipher\.Blowfish\s*\(', re.IGNORECASE),
        "description": "Blowfish has a small block size, making it vulnerable to attacks.",
        "recommendation": "Use AES-256 instead."
    },
    {
        "name": "Use of Weak Encryption Algorithm (RC4)",
        "pattern": re.compile(r'ARC4\.new\s*\(', re.IGNORECASE),
        "description": "RC4 has known vulnerabilities and should not be used.",
        "recommendation": "Use AES-GCM or ChaCha20-Poly1305 instead."
    }
]

def scan_for_weak_ciphers(directory):
    """Scans Python files for weak cryptographic algorithms."""
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln in WEAK_CIPHER_PATTERNS:
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

def export_to_csv(results, output_file="weak_ciphers_scan_results.csv"):
    """Exports scan results to a CSV file."""
    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"📄 Results exported to CSV: {output_file}")

def export_to_excel(results, output_file="weak_ciphers_scan_results.xlsx"):
    """Exports scan results to an Excel file."""
    df = pd.DataFrame(results)
    df.to_excel(output_file, index=False)
    print(f"📊 Results exported to Excel: {output_file}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for weak cipher usage...")
    vulnerabilities_found = scan_for_weak_ciphers(folder_to_scan)

    if vulnerabilities_found:
        print("\n🚨 Weak Cipher Algorithms Found:")
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
        print("✅ No weak cipher usage found!")

if __name__ == "__main__":
    main()
