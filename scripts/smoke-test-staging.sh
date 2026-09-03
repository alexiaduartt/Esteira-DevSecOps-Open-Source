#!/usr/bin/env bash
# =============================================================================
# PBI-53 — Smoke Test do ambiente de Staging
# Valida que os endpoints críticos estão respondendo após o deploy.
# =============================================================================
set -euo pipefail

STAGING_URL="${STAGING_URL:-http://localhost:3001}"
ENDPOINTS=("/" "/health")
FAILED=0

echo "=============================================="
echo "[INFO] [Smoke Test] PBI-53 — Validação Staging"
echo "=============================================="
echo "[INFO] [Smoke Test] URL base: ${STAGING_URL}"

for EP in "${ENDPOINTS[@]}"; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${STAGING_URL}${EP}" 2>/dev/null || echo "000")

  if [[ "${HTTP_CODE}" =~ ^2[0-9]{2}$ ]]; then
    echo "[OK]    [Smoke Test] ${EP} → HTTP ${HTTP_CODE}"
  else
    echo "[ERROR] [Smoke Test] ${EP} → HTTP ${HTTP_CODE}"
    FAILED=1
  fi
done

# Validar conteúdo do health check
if [ "${FAILED}" -eq 0 ]; then
  HEALTH_RESPONSE=$(curl -s "${STAGING_URL}/health" 2>/dev/null || echo "{}")
  STATUS=$(echo "${HEALTH_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")

  if [ "${STATUS}" = "UP" ]; then
    echo "[OK]    [Smoke Test] Health check retornou status=UP"
  else
    echo "[WARN]  [Smoke Test] Health check retornou status='${STATUS}' (esperado: UP)"
  fi
fi

echo "=============================================="
if [ "${FAILED}" -eq 1 ]; then
  echo "[ERROR] [Smoke Test] Um ou mais endpoints falharam."
  exit 1
fi

echo "[OK]    [Smoke Test] Todos os endpoints validados com sucesso."
