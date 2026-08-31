#!/usr/bin/env bash
# Sauvegarde automatique d'etcd pour le cluster devsecops-lab (Kind)
#
# Méthode : etcdctl a été copié une fois pour toutes dans /usr/local/bin/ du
# conteneur du nœud (docker exec devsecops-lab-control-plane), où les outils
# standards (cat, mkdir, cp) sont disponibles - contrairement au pod etcd lui-même,
# dont l'image est volontairement minimale (durcissement de sécurité).
set -euo pipefail

CONTAINER="devsecops-lab-control-plane"
DATE=$(date +%Y%m%d-%H%M%S)
SNAPSHOT_NAME="snapshot-${DATE}.db"
BACKUP_DIR_CONTAINER="/var/lib/etcd-backup"
BACKUP_DIR_HOST="$HOME/etcd-backups"
RETENTION_DAYS=7

mkdir -p "$BACKUP_DIR_HOST"
docker exec "$CONTAINER" mkdir -p "$BACKUP_DIR_CONTAINER"

echo "[$(date)] Démarrage du snapshot etcd..."

docker exec "$CONTAINER" etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save "${BACKUP_DIR_CONTAINER}/${SNAPSHOT_NAME}"

docker cp "${CONTAINER}:${BACKUP_DIR_CONTAINER}/${SNAPSHOT_NAME}" "${BACKUP_DIR_HOST}/${SNAPSHOT_NAME}"

echo "[$(date)] Snapshot copié vers ${BACKUP_DIR_HOST}/${SNAPSHOT_NAME}"

docker exec "$CONTAINER" rm -f "${BACKUP_DIR_CONTAINER}/${SNAPSHOT_NAME}"

find "$BACKUP_DIR_HOST" -name "snapshot-*.db" -mtime +${RETENTION_DAYS} -delete

echo "[$(date)] Sauvegarde terminée. Fichiers conservés :"
ls -lh "$BACKUP_DIR_HOST"
# --- Publication des métriques Prometheus (via node_exporter textfile) ---
METRICS_DIR_CONTAINER="/var/lib/node-exporter/textfile"
SNAPSHOT_SIZE=$(stat -c%s "${BACKUP_DIR_HOST}/${SNAPSHOT_NAME}")
SNAPSHOT_COUNT=$(find "$BACKUP_DIR_HOST" -name "snapshot-*.db" | wc -l)
NOW_TS=$(date +%s)

cat > /tmp/etcd_backup.prom <<METRICS
# HELP etcd_backup_last_success_timestamp_seconds Horodatage de la derniere sauvegarde etcd reussie
# TYPE etcd_backup_last_success_timestamp_seconds gauge
etcd_backup_last_success_timestamp_seconds ${NOW_TS}
# HELP etcd_backup_size_bytes Taille du dernier snapshot etcd
# TYPE etcd_backup_size_bytes gauge
etcd_backup_size_bytes ${SNAPSHOT_SIZE}
# HELP etcd_backup_count Nombre de snapshots conserves
# TYPE etcd_backup_count gauge
etcd_backup_count ${SNAPSHOT_COUNT}
METRICS

docker exec "$CONTAINER" mkdir -p "$METRICS_DIR_CONTAINER"
docker cp /tmp/etcd_backup.prom "${CONTAINER}:${METRICS_DIR_CONTAINER}/etcd_backup.prom.tmp"
docker exec "$CONTAINER" mv "${METRICS_DIR_CONTAINER}/etcd_backup.prom.tmp" "${METRICS_DIR_CONTAINER}/etcd_backup.prom"
rm -f /tmp/etcd_backup.prom
echo "[$(date)] Métriques Prometheus publiées."
