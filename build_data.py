import os
import json
import glob

# Normalized mapping for the Y-Axis
ECOSYSTEMS = ["npm", "pypi", "maven", "go", "cargo", "nuget", "packagist", "rubygems"]
ECOSYSTEM_MAP = {name: i for i, name in enumerate(ECOSYSTEMS)}

def extract_severity(vuln):
    # Try parsing standard CVSS scores first
    for sev in vuln.get("severity", []):
        if "score" in sev and sev["score"]:
            try:
                return float(sev["score"])
            except (ValueError, TypeError):
                continue
    
    # Fallback to text-based severities if numeric score is missing
    db_specific = vuln.get("database_specific", {})
    severity_str = db_specific.get("severity", "").upper() if db_specific else ""
    mapping = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "LOW": 2.5}
    return mapping.get(severity_str, 0.0)

def main():
    records = []
    
    # Search the cloned repository path
    search_path = os.path.join("advisories", "advisories", "github-reviewed", "**", "*.json")
    
    for file_path in glob.glob(search_path, recursive=True):
        try:
            with open(file_path, "r") as f:
                vuln = json.load(f)
            
            # Skip withdrawn advisories
            if "withdrawn" in vuln:
                continue
                
            published = vuln.get("published", "")[:10]  # Format: YYYY-MM-DD
            if not published:
                continue
                
            # Extract ecosystem
            affected = vuln.get("affected", [])
            if not affected or "package" not in affected[0]:
                continue
                
            ecosystem_str = affected[0]["package"].get("ecosystem", "").lower()
            
            if ecosystem_str in ECOSYSTEM_MAP:
                score = extract_severity(vuln)
                if score > 0.0:
                    # Compressed flat array: [Date, Registry Index, CVSS Score, ID]
                    records.append([published, ECOSYSTEM_MAP[ecosystem_str], score, vuln.get("id")])
                    
        except Exception:
            continue

    # Output minimized JSON payload
    output = {
        "meta": {"ecosystems": ECOSYSTEMS},
        "data": records
    }
    
    with open("data.json", "w") as f:
        json.dump(output, f, separators=(',', ':'))

if __name__ == "__main__":
    main()
