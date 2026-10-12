#!/usr/bin/env bash
# Generate the benign lab pcap and run Suricata over it offline; eve.json lands in the shared volume Wazuh reads.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/make_pcap.py pcaps/siemlab.pcap
docker compose run --rm --entrypoint suricata suricata -r /pcaps/siemlab.pcap -S /etc/suricata/rules/local.rules -k none -l /var/log/suricata
docker compose run --rm --entrypoint sh suricata -c 'grep "\"event_type\":\"alert\"" /var/log/suricata/eve.json | tail -n 20' | tee results/suricata_alerts.jsonl
# Live alternative: sudo tcpreplay -i "$SURICATA_IFACE" pcaps/siemlab.pcap
