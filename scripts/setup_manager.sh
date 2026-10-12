#!/usr/bin/env bash
# Add the localfile blocks to the manager and restart it.
set -euo pipefail
docker compose exec wazuh.manager bash -c 'grep -q siemlab /var/ossec/etc/ossec.conf || { echo "<ossec_config><!-- siemlab -->"; grep -v "^<!--" /wazuh-config-mount/etc/shared/siemlab-localfile.conf; echo "</ossec_config>"; } >> /var/ossec/etc/ossec.conf'
docker compose exec wazuh.manager /var/ossec/bin/wazuh-control restart
