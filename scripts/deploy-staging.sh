#!/usr/bin/env bash
# =============================================================================
# PBI-53 — Deploy automatizado para ambiente de Staging
# Uso: deploy-staging.sh <commit-sha>
# =============================================================================
set -euo pipefail

DEPLOY_SHA="${1:?Uso: deploy-staging.sh <commit-sha>}"
REPO="${GITHUB_REPOSITORY:?Variável GITHUB_REPOSITORY não definida}"
REPO_LC=$(echo "${REPO}" | tr '[:upper:]' '[:lower:]')
IMAGE_REF="ghcr.io/${REPO_LC}:staging-${DEPLOY_SHA}"
COMPOSE_FILE="docker-compose.staging.yml"
HEALTH_URL="${STAGING_URL:-http://localhost:3001}/health"
MAX_RETRIES=12
RETRY_INTERVAL=5

echo "=============================================="
echo "[INFO] [Staging] PBI-53 — Deploy de Staging"
echo "=============================================="
echo "[INFO] [Staging] Imagem: ${IMAGE_REF}"
echo "[INFO] [Staging] Compose: ${COMPOSE_FILE}"
echo "[INFO] [Staging] Health URL: ${HEALTH_URL}"

# Validar que o compose file existe
if [ ! -f "${COMPOSE_FILE}" ]; then
  echo "[ERROR] [Staging] Arquivo ${COMPOSE_FILE} não encontrado."
  exit 1
fi

# Deploy com Docker Compose
export DEPLOY_SHA
export GITHUB_REPOSITORY="${REPO}"

docker compose -f "${COMPOSE_FILE}" pull
docker compose -f "${COMPOSE_FILE}" up -d --force-recreate --remove-orphans

# Smoke Test — aguardar health check
echo "[INFO] [Staging] Aguardando health check em ${HEALTH_URL}..."
for i in $(seq 1 ${MAX_RETRIES}); do
  if curl -sf "${HEALTH_URL}" > /dev/null 2>&1; then
    RESPONSE=$(curl -s "${HEALTH_URL}")
    echo "[OK] [Staging] Aplicação disponível após ${i} tentativas."
    echo "[INFO] [Staging] Response: ${RESPONSE}"
    exit 0
  fi
  echo "[WAIT] [Staging] Tentativa ${i}/${MAX_RETRIES}..."
  sleep "${RETRY_INTERVAL}"
done

echo "[ERROR] [Staging] Health check falhou após ${MAX_RETRIES} tentativas."
echo "[INFO] [Staging] Últimos logs do container:"
docker compose -f "${COMPOSE_FILE}" logs --tail=50
exit 1
