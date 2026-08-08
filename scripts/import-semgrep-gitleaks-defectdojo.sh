#!/bin/bash
# =============================================================================
# import-semgrep-gitleaks-defectdojo.sh
# PBI-28 / Task 140 — Realizar importação manual para teste
#
# Template de importação dos relatórios Semgrep e GitLeaks no DefectDojo
# via API REST (/api/v2/import-scan/).
#
# Variáveis de ambiente necessárias:
#   DEFECTDOJO_URL   — URL base do DefectDojo (ex: https://defectdojo.example.com)
#   DEFECTDOJO_TOKEN — Token de API do DefectDojo
#   ENGAGEMENT_ID    — ID do engagement onde os scans serão importados
#
# Uso:
#   export DEFECTDOJO_URL="https://defectdojo.example.com"
#   export DEFECTDOJO_TOKEN="seu-token-aqui"
#   export ENGAGEMENT_ID="1"
#   bash scripts/import-semgrep-gitleaks-defectdojo.sh
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

DEFECTDOJO_URL="${DEFECTDOJO_URL:-}"
DEFECTDOJO_TOKEN="${DEFECTDOJO_TOKEN:-}"
ENGAGEMENT_ID="${ENGAGEMENT_ID:-}"

REPORTS_DIR="reports"
SEMGREP_REPORT="$REPORTS_DIR/semgrep/semgrep-results.json"
GITLEAKS_REPORT="$REPORTS_DIR/gitleaks/gitleaks-results.json"

IMPORT_ENDPOINT="/api/v2/import-scan/"

RESULTS_DIR="$REPORTS_DIR/defectdojo"
IMPORT_LOG="$RESULTS_DIR/import-log.json"

# ---------------------------------------------------------------------------
# Validações iniciais
# ---------------------------------------------------------------------------

echo "══════════════════════════════════════════════════════════════"
echo "  PBI-28 │ Importação Semgrep + GitLeaks → DefectDojo"
echo "══════════════════════════════════════════════════════════════"
echo ""

if [ -z "$DEFECTDOJO_URL" ]; then
  echo "❌ DEFECTDOJO_URL não definida. Configure a variável de ambiente."
  exit 1
fi

if [ -z "$DEFECTDOJO_TOKEN" ]; then
  echo "❌ DEFECTDOJO_TOKEN não definido. Configure a variável de ambiente."
  exit 1
fi

if [ -z "$ENGAGEMENT_ID" ]; then
  echo "❌ ENGAGEMENT_ID não definido. Configure a variável de ambiente."
  exit 1
fi

mkdir -p "$RESULTS_DIR"

# ---------------------------------------------------------------------------
# Função de importação
# ---------------------------------------------------------------------------

import_scan() {
  local scan_type="$1"
  local report_file="$2"
  local test_title="$3"
  local tool_name="$4"

  echo "── Importando: $tool_name ──"

  if [ ! -f "$report_file" ]; then
    echo "  ⚠️  Relatório não encontrado: $report_file"
    echo "  Pulando importação de $tool_name."
    echo ""
    echo "{\"tool\": \"$tool_name\", \"status\": \"skipped\", \"reason\": \"file_not_found\"}" >> "$IMPORT_LOG"
    return 0
  fi

  local SIZE
  SIZE=$(stat -c%s "$report_file" 2>/dev/null || stat -f%z "$report_file" 2>/dev/null || echo "0")
  echo "  Arquivo: $report_file ($SIZE bytes)"
  echo "  scan_type: $scan_type"
  echo "  Engagement: $ENGAGEMENT_ID"

  local HTTP_RESPONSE
  HTTP_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${DEFECTDOJO_URL}${IMPORT_ENDPOINT}" \
    -H "Authorization: Token ${DEFECTDOJO_TOKEN}" \
    -F "scan_type=${scan_type}" \
    -F "file=@${report_file}" \
    -F "engagement=${ENGAGEMENT_ID}" \
    -F "active=true" \
    -F "verified=false" \
    -F "test_title=${test_title}" \
    2>&1) || true

  local HTTP_BODY
  local HTTP_CODE
  HTTP_BODY=$(echo "$HTTP_RESPONSE" | head -n -1)
  HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n 1)

  echo "  HTTP Status: $HTTP_CODE"

  if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ] 2>/dev/null; then
    echo "  ✅ Importação concluída com sucesso!"
    echo "{\"tool\": \"$tool_name\", \"status\": \"success\", \"http_code\": $HTTP_CODE, \"scan_type\": \"$scan_type\"}" >> "$IMPORT_LOG"
  else
    echo "  ❌ Falha na importação."
    echo "  Resposta: $HTTP_BODY"
    echo "{\"tool\": \"$tool_name\", \"status\": \"failed\", \"http_code\": \"$HTTP_CODE\", \"response\": \"$HTTP_BODY\"}" >> "$IMPORT_LOG"
  fi

  echo ""
}

# ---------------------------------------------------------------------------
# Execução das importações
# ---------------------------------------------------------------------------

# Limpar log anterior
echo "[]" > "$IMPORT_LOG"

# 1. Semgrep → DefectDojo
import_scan \
  "Semgrep JSON Report" \
  "$SEMGREP_REPORT" \
  "Semgrep SAST Scan - Pipeline DevSecOps" \
  "semgrep"

# 2. GitLeaks → DefectDojo
import_scan \
  "Gitleaks Scan" \
  "$GITLEAKS_REPORT" \
  "GitLeaks Secret Scan - Pipeline DevSecOps" \
  "gitleaks"

# ---------------------------------------------------------------------------
# Resumo
# ---------------------------------------------------------------------------

echo "══════════════════════════════════════════════════════════════"
echo "  Resumo da Importação"
echo "══════════════════════════════════════════════════════════════"
echo "  Log de importação salvo em: $IMPORT_LOG"
echo "  DefectDojo URL: $DEFECTDOJO_URL"
echo "  Engagement ID: $ENGAGEMENT_ID"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "Importação concluída."
