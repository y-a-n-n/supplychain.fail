#!/bin/bash

# Exit immediately if any command fails
set -e

echo "🔄 Starting CVE Data Sync..."

# 1. Shallow Clone GitHub Advisory DB
echo "📥 Cloning GitHub Advisory DB (shallow)..."
git clone --depth 1 https://github.com/github/advisory-database.git advisories

# 2. Generate Optimized JSON Dataset
echo "🐍 Running Python script to build dataset..."
# Uses python3, assuming it's mapped to Python 3.11+ on your local machine
python3 build_data.py

# 3. Purge Heavy Clone Folder
echo "🧹 Cleaning up clone folder..."
rm -rf advisories

echo "✅ Local CVE data sync complete!"