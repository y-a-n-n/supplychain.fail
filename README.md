# supplychain.fail

A weekly vulnerability volume matrix tracking open-source registries and the Linux kernel.

Data is ingested from the GitHub Advisory Database and OSV, filtered by CVSS severity, and compiled into a lightweight JSON payload rendered via a static ECharts heatmap.

## Stack

* **Frontend:** Tailwind CSS, Apache ECharts (Single `index.html`)
* **Ingestion:** Python 3 (Zero-dependency)
* **Automation:** GitHub Actions

## Local Development

```bash
# 1. Fetch latest datasets and compile data.json
./sync_cve_data.sh

# 2. Spin up a local server
python3 -m http.server 8080

```

Open `http://localhost:8080`.

## Data Pipeline

Automated by `.github/workflows/import-data.yml` on a daily cron:

1. Shallow clones the GHSA repo.
2. Pulls the latest native OSV Linux Kernel zip.
3. Runs `build_data.py` to compute CVSS vectors, filter noise (Linux records are restricted to official CVEs $\ge$ 7.0), and bucket events by week.
4. Commits the compressed `data.json` back to `main`.