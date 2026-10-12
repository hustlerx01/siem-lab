#!/usr/bin/env bash
# Feed each sample event into wazuh-logtest inside the manager and save output.
set -euo pipefail
cd "$(dirname "$0")/.."
out=results/wazuh_logtest.txt; : > "$out"
for f in samples/*.jsonl; do
  while IFS= read -r line; do
    echo "### $f" >> "$out"
    printf '%s\n' "$line" | docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -q 2>&1 >> "$out" || true
  done < "$f"
done
grep -E "id: '1001|Alert to be generated" "$out" | sort | uniq -c
