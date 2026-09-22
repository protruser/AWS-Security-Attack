#!/usr/bin/env bash
# Installs everything the dashboard's 7 scenarios shell out to.
# Python deps (just Flask) are separate — see requirements.txt.
set -euo pipefail

APT_PACKAGES=(
  sqlmap     # SQL Injection
  zaproxy    # Cross-Site Scripting (provides the `zaproxy` CLI)
  gobuster   # Directory Search
  hydra      # Login Brute Force
  nmap       # Port Scan
  awscli     # Credential Misuse
  trivy      # Vulnerable Image
)

echo "Installing: ${APT_PACKAGES[*]}"
sudo apt update
sudo apt install -y "${APT_PACKAGES[@]}"

echo
echo "Done. Checking each tool is on PATH:"
for bin in sqlmap zaproxy gobuster hydra nmap aws trivy; do
  printf '  %-10s ' "$bin"
  command -v "$bin" >/dev/null 2>&1 && echo "ok ($(command -v "$bin"))" || echo "MISSING"
done
