#!/usr/bin/env bash
# Start an isolated Wazuh 4.7.5 manager with this repository's rules, ready for
#   python3 scripts/run_wazuh_fixtures.py --container <name> --transport eventchannel
#
# Local and throwaway: no published ports, no API password, no agents. Only
# synthetic fixtures are sent to it. It enables <logall_json> inside the
# container, because the runner proves each event was evaluated through
# archives.json. Remove it afterwards with: docker rm -f <name>
set -euo pipefail

NAME=${1:-wazuh-fixtures}
IMAGE=wazuh/wazuh-manager:4.7.5
ROOT=$(cd "$(dirname "$0")/.." && pwd)

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  for attempt in 1 2 3; do
    docker pull -q "$IMAGE" && break
    [ "$attempt" = 3 ] && { echo "could not pull $IMAGE" >&2; exit 1; }
    sleep $((attempt * 20))
  done
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --hostname "$NAME" \
  -e INDEXER_URL= -e FILEBEAT_SSL_VERIFICATION_MODE=none \
  -v "$ROOT/detection-rules/custom-wazuh-rules.xml:/wazuh-config-mount/etc/rules/local_rules.xml:ro" \
  "$IMAGE" >/dev/null

wait_ready() {
  local status
  for _ in $(seq 1 90); do
    # Read status first: "| grep -q" would SIGPIPE wazuh-control under pipefail.
    status=$(docker exec "$NAME" /var/ossec/bin/wazuh-control status 2>/dev/null || true)
    if [[ $status == *"wazuh-analysisd is running"* ]] \
      && docker exec "$NAME" test -S /var/ossec/queue/sockets/queue; then
      return 0
    fi
    sleep 2
  done
  echo "wazuh-analysisd did not start in $NAME" >&2
  docker logs --tail 50 "$NAME" >&2
  return 1
}

wait_ready
docker exec "$NAME" /var/ossec/bin/wazuh-analysisd -t
docker exec "$NAME" sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' /var/ossec/etc/ossec.conf
docker exec "$NAME" grep -q '<logall_json>yes</logall_json>' /var/ossec/etc/ossec.conf
docker exec "$NAME" /var/ossec/bin/wazuh-control restart >/dev/null
wait_ready
echo "ready: $NAME"
