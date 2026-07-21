#!/usr/bin/env bash
set -euo pipefail

REPORTS_DIR="./reports"
THRESHOLD=${THRESHOLD:-5}

count_critical() {
  local file=$1
  local count=0
  if [[ ! -f "$file" ]]; then
    echo "0"
    return
  fi

  # Semgrep JSON: считаем severity: "error" и OWASP Top 10 A01/A03/A05
  if [[ "$file" == *semgrep* ]]; then
    count=$(jq '[.results[] | select(.extra.severity == "error" or (.extra.metadata.owasp_top_10 // "") | contains("A01") or contains("A03") or contains("A05"))] | length' "$file" 2>/dev/null || echo 0)
  # Gitleaks JSON: high/critical
  elif [[ "$file" == *gitleaks* ]]; then
    count=$(jq '[.[] | select(.severity == "high" or .severity == "critical")] | length' "$file" 2>/dev/null || echo 0)
  # Trivy JSON: severity >= 7 (critical/high)
  elif [[ "$file" == *trivy* ]]; then
    count=$(jq 'reduce .Vulnerabilities[] as $v (0; if ($v.Severity | tonumber) >= 7 then .+1 else . end)' "$file" 2>/dev/null || echo 0)
  # Nuclei JSONL: ищем строки с "severity": "critical" или "high"
  elif [[ "$file" == *nuclei* ]]; then
    count=$(grep -c '"severity": *"critical"\|"severity": *"high"' "$file" || echo 0)
  else
    count=0
  fi
  echo "$count"
}

total_critical=0

for report in "$REPORTS_DIR"/*.json "$REPORTS_DIR"/*.jsonl; do
  if [[ -f "$report" ]]; then
    c=$(count_critical "$report")
    echo "[INFO] Report: $(basename "$report") -> critical/high count: $c"
    total_critical=$((total_critical + c))
  fi
done

echo "[INFO] Total critical/high findings: $total_critical"

if [[ $total_critical -gt $THRESHOLD ]]; then
  echo "[ERROR] Security gate FAILED: total findings ($total_critical) exceed threshold ($THRESHOLD)"
  exit 1
else
  echo "[OK] Security gate PASSED"
  exit 0
fi