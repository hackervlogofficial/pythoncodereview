import os
import re
import csv
import pandas as pd

# Define patterns to detect GraphQL DoS vulnerabilities in Python code
VULNERABILITY_PATTERNS = [
    {
        "name": "GraphQL Query Depth Not Limited",
        "pattern": re.compile(r'(query_depth|max_depth)\s*=\s*None', re.IGNORECASE),
        "description": "No depth limit set for GraphQL queries, making the API vulnerable to deeply nested queries.",
        "recommendation": "Set a query depth limit using middleware or libraries like `graphql-depth-limit`."
    },
    {
        "name": "GraphQL Query Complexity Not Limited",
        "pattern": re.compile(r'(query_complexity|max_complexity)\s*=\s*None', re.IGNORECASE),
        "description": "GraphQL API does not restrict query complexity, making it vulnerable to resource exhaustion attacks.",
        "recommendation": "Implement a complexity limit to prevent excessive computational load."
    },
    {
        "name": "No Rate Limiting on GraphQL API",
        "pattern": re.compile(r'(rate_limit|throttle|throttling)\s*=\s*False', re.IGNORECASE),
        "description": "GraphQL API does not have rate limiting enabled, allowing attackers to send unlimited queries.",
        "recommendation": "Use rate-limiting middleware (e.g., Flask-Limiter, Django Ratelimit) to prevent abuse."
    }
]

def scan_for_vulnerabilities(directory):
    """Scans Python files for GraphQL DoS vulnerabilities."""
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
                                "Vulnerability": vuln["name"],
                                "File Path": file_path,
                                "Line No.": line_no,
                                "Description": vuln["description"],
                                "Vulnerable Code": line.strip(),
                                "Recommendation": vuln["recommendation"]
                            })

    return results

def save_to_csv(results, output_dir):
    """Saves the scan results to a CSV file."""
    csv_file = os.path.join(output_dir, "graphql_vulnerabilities.csv")

    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\n📁 CSV Report saved: {csv_file}")

def save_to_excel(results, output_dir):
    """Saves the scan results to an Excel file."""
    excel_file = os.path.join(output_dir, "graphql_vulnerabilities.xlsx")

    df = pd.DataFrame(results)
    df.to_excel(excel_file, index=False)

    print(f"📁 Excel Report saved: {excel_file}")

def main():
    folder_to_scan = input("Enter the folder path containing Python source code: ").strip()

    if not os.path.exists(folder_to_scan):
        print("❌ Invalid folder path! Please enter a valid path.")
        return

    print("\n🔍 Scanning for GraphQL DoS vulnerabilities...")
    vulnerabilities_found = scan_for_vulnerabilities(folder_to_scan)

    if vulnerabilities_found:
        print("\n🔴 Potential GraphQL DoS Issues Found:")
        for vuln in vulnerabilities_found:
            print(f"\n📌 Vulnerability: {vuln['Vulnerability']}")
            print(f"📍 Location: {vuln['File Path']} (Line {vuln['Line No.']})")
            print(f"📝 Description: {vuln['Description']}")
            print(f"⚠️ Vulnerable Code: {vuln['Vulnerable Code']}")
            print(f"✅ Recommendation: {vuln['Recommendation']}")
            print("-" * 80)

        # Create output directory if it doesn't exist
        output_dir = "scan_results"
        os.makedirs(output_dir, exist_ok=True)

        # Export results
        save_to_csv(vulnerabilities_found, output_dir)
        save_to_excel(vulnerabilities_found, output_dir)

    else:
        print("✅ No GraphQL DoS vulnerabilities found!")

if __name__ == "__main__":
    main()
