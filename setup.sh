#!/bin/bash
# setup.sh — New user onboarding for the SIEM homelab
# Run this inside the Wazuh VM after cloning wazuh-docker.
# Assumes Ubuntu 22.04, Docker already installed.
#
# Usage: bash setup.sh

set -e

COMPOSE_DIR="$HOME/wazuh-docker/single-node"
WAZUH_VERSION="v4.9.2"

echo "=== SIEM Lab Setup ==="
echo ""

# 1 — Check Docker
if ! command -v docker &>/dev/null; then
  echo "[ERROR] Docker not found. Install it first:"
  echo "  curl -fsSL https://get.docker.com | sudo sh"
  echo "  sudo usermod -aG docker \$USER && newgrp docker"
  exit 1
fi

if ! docker compose version &>/dev/null; then
  echo "[ERROR] Docker Compose plugin not found. Install:"
  echo "  sudo apt install docker-compose-plugin -y"
  exit 1
fi

echo "[OK] Docker and Docker Compose found"

# 2 — Clone wazuh-docker if not present
if [ ! -d "$COMPOSE_DIR" ]; then
  echo "=== Cloning wazuh-docker $WAZUH_VERSION ==="
  git clone https://github.com/wazuh/wazuh-docker.git "$HOME/wazuh-docker" --depth=1 --branch "$WAZUH_VERSION"
fi

echo "[OK] wazuh-docker present at $COMPOSE_DIR"

# 3 — Generate SSL certificates
echo "=== Generating SSL certificates ==="
cd "$COMPOSE_DIR"
docker compose -f generate-indexer-certs.yml run --rm generator
echo "[OK] Certs generated"

# 4 — Custom config files
echo ""
echo "=== Config file setup ==="
echo ""
echo "You need to provide three custom config files from your backup:"
echo ""
echo "  1. ossec.conf wodle — the aws-s3 module block"
echo "     Copy into: $COMPOSE_DIR/config/wazuh_cluster/wazuh_manager.conf"
echo "     Look for the <wodle name=\"aws-s3\"> section and paste it before"
echo "     the last </ossec_config> tag. Replace bucket name and credentials."
echo ""
echo "  2. local_rules.xml — your custom detection rules"
echo "     Copy to: $COMPOSE_DIR/config/wazuh_cluster/local_rules.xml"
echo ""
echo "  3. Passwords — edit docker-compose.yml and set three fields:"
echo ""
echo "     INDEXER_PASSWORD  — controls the OpenSearch admin account."
echo "                         This is the password you use to log into"
echo "                         the Wazuh dashboard in the browser (user: admin)."
echo ""
echo "     API_PASSWORD      — controls the Wazuh REST API (port 55000)."
echo "                         Used by the dashboard backend to talk to the manager."
echo ""
echo "     DASHBOARD_PASSWORD — internal service account for the dashboard."
echo "                          Not your browser login — it's dashboard→indexer auth."
echo ""
echo "     Set all three to strong values before starting the stack."
echo "     These are Docker env vars — no bcrypt hash needed here. The containers"
echo "     handle hashing on first boot when volumes are created fresh."
echo ""
echo "     IMPORTANT: the env var only takes effect on first boot (empty volumes)."
echo "     If you need to change the password on a running stack, use:"
echo "       docker compose down -v && docker compose up -d"
echo "     This wipes volumes (and alert history) and reinitialises with the"
echo "     new password. To change it without data loss, see the Wazuh docs"
echo "     on the OpenSearch securityadmin tool."
echo ""
echo "     To find all password fields in the compose file:"
echo "       grep -i password $COMPOSE_DIR/docker-compose.yml"
echo ""
echo "Press Enter when your config files and passwords are set..."
read -r

# 5 — Start the stack
echo "=== Starting Wazuh stack ==="
docker compose up -d

echo "=== Waiting 60s for indexer to initialise ==="
sleep 60

# 6 — ar.conf first-boot fix
if ! docker compose exec -T wazuh.manager test -f /var/ossec/etc/shared/ar.conf 2>/dev/null; then
  echo "=== ar.conf missing — first boot fix ==="
  docker compose exec -T wazuh.manager bash -c "mkdir -p /var/ossec/etc/shared && touch /var/ossec/etc/shared/ar.conf"
  docker compose restart wazuh.manager
  sleep 20
fi

# 7 — Status
echo ""
echo "=== Stack status ==="
docker compose ps
echo ""
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control status

echo ""
echo "=== Setup complete ==="
echo ""
echo "Dashboard: https://<your-vm-ip> (accept the self-signed cert)"
echo "  Chrome: use SSH tunnel: ssh -L 8443:localhost:443 user@<vm-ip>"
echo "  then browse https://127.0.0.1:8443"
echo ""
echo "Login: admin / (the password you set in docker-compose.yml)"
echo ""
echo "Next steps:"
echo "  - Enroll agents: Wazuh dashboard → Agents → Add agent"
echo "  - Verify CloudTrail pipeline: check /var/ossec/logs/ossec.log for aws-s3 pull entries"
echo "  - Review scenarios/ in the project repo for attack simulations to run"
