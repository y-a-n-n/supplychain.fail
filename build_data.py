import os
import json
import glob
import math

ECOSYSTEMS = ["npm", "pypi", "maven", "go", "cargo", "nuget", "packagist", "rubygems"]
ECOSYSTEM_MAP = {name: i for i, name in enumerate(ECOSYSTEMS)}

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def round_up_cvss(value):
    return math.ceil(value * 10) / 10.0


def parse_cvss_v3_vector(vector):
    if not isinstance(vector, str) or not vector.startswith("CVSS:3."):
        return None

    parts = vector.split("/")
    metrics = {}

    for part in parts[1:]:
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metrics[key] = val

    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    if not all(k in metrics for k in required):
        return None

    try:
        iss = 1 - ((1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]]))

        if metrics["S"] == "U":
            impact = 6.42 * iss
            pr = PR_U[metrics["PR"]]
        elif metrics["S"] == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            pr = PR_C[metrics["PR"]]
        else:
            return None

        exploitability = 8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] * pr * UI[metrics["UI"]]

        if impact <= 0:
            return 0.0

        if metrics["S"] == "U":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)

        return round_up_cvss(score)
    except KeyError:
        return None


def normalize_ecosystem(raw_ecosystem):
    raw = (raw_ecosystem or "").strip()

    if raw in ["crates.io", "Cargo", "cargo", "Rust", "rust"]:
        return "cargo"

    return raw.lower()


def extract_severity(vuln):
    for sev in vuln.get("severity", []):
        score = sev.get("score")
        if not score:
            continue

        if isinstance(score, (int, float)):
            return float(score)

        if isinstance(score, str):
            try:
                return float(score)
            except (ValueError, TypeError):
                parsed = parse_cvss_v3_vector(score)
                if parsed is not None:
                    return parsed

    db_specific = vuln.get("database_specific", {}) or {}
    severity_str = db_specific.get("severity", "").upper()
    mapping = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MODERATE": 5.5,
        "MEDIUM": 5.5,
        "LOW": 2.5
    }
    return mapping.get(severity_str, 0.0)


def main():
    records = []
    seen = set()
    search_path = os.path.join("advisories", "advisories", "github-reviewed", "**", "*.json")

    for file_path in glob.glob(search_path, recursive=True):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                vuln = json.load(f)

            if "withdrawn" in vuln:
                continue

            published = vuln.get("published", "")[:10]
            if not published:
                continue

            vuln_id = vuln.get("id", "")
            score = extract_severity(vuln)
            if score <= 0.0:
                continue

            affected = vuln.get("affected", [])
            if not affected:
                continue

            for aff in affected:
                pkg = aff.get("package", {}) or {}
                ecosystem_str = normalize_ecosystem(pkg.get("ecosystem", ""))

                if ecosystem_str not in ECOSYSTEM_MAP:
                    continue

                dedupe_key = (published, ecosystem_str, vuln_id)
                if dedupe_key in seen:
                    continue

                seen.add(dedupe_key)
                records.append([published, ECOSYSTEM_MAP[ecosystem_str], score, vuln_id])

        except Exception:
            continue

    output = {
        "meta": {"ecosystems": ECOSYSTEMS},
        "data": records
    }

    with open("data.json", "w", encoding="utf-8") as f:
        json.dump(output, f, separators=(",", ":"))


if __name__ == "__main__":
    main()