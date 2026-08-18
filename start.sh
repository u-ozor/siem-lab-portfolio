#!/bin/bash
cd /home/wazuhppp/wazuh-docker/single-node

echo "=== Starting Wazuh stack ==="
docker compose up -d

echo "=== Waiting for indexer (60s) ==="
sleep 60

# ar.conf only missing on first boot after a fresh volume — check before acting
if ! docker compose exec -T wazuh.manager test -f /var/ossec/etc/shared/ar.conf 2>/dev/null; then
    echo "=== ar.conf missing — first boot fix ==="
    docker compose exec -T wazuh.manager bash -c "mkdir -p /var/ossec/etc/shared && touch /var/ossec/etc/shared/ar.conf"
    docker compose restart wazuh.manager
    sleep 20
fi

echo "=== Status ==="
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control status
docker compose ps
