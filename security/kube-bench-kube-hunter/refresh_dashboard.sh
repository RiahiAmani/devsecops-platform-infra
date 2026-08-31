#!/bin/bash
# refresh_dashboard.sh — relance les scans de sécurité et régénère le dashboard en une seule commande.
set -e

CLUSTER_CONTAINER="devsecops-lab-control-plane"
API_SERVER_IP="172.18.0.2"

echo "→ Scan kube-hunter en cours..."
docker run --rm --network kind aquasec/kube-hunter --remote "$API_SERVER_IP" --report json --log none > kube-hunter-report.json

echo "→ Scan kube-bench en cours..."
docker exec "$CLUSTER_CONTAINER" sh -c "cd / && ./kube-bench run --config-dir ./cfg --config ./cfg/config.yaml --benchmark cis-1.24 --json" > kube-bench-report.json

echo "→ Génération du dashboard..."
python3 generate_dashboard.py --bench kube-bench-report.json --hunter kube-hunter-report.json

echo ""
echo "✅ Dashboard mis à jour : dashboard.html"
echo "   Rafraîchis simplement ton navigateur sur http://$(hostname -I | awk '{print $1}'):8080/dashboard.html"
