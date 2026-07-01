#!/usr/bin/env bash

set -euo pipefail

# importa relatórios de segurança no defectdojo
# usa variáveis de ambiente pra evitar token ou url fixa no código

DRY_RUN=false

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "uso:"
  echo "  bash scripts/import-security-reports-defectdojo.sh --dry-run"
  echo "  bash scripts/import-security-reports-defectdojo.sh"
  echo ""
  echo "variáveis obrigatórias pra importação real:"
  echo "  DEFECTDOJO_URL"
  echo "  DEFECTDOJO_TOKEN"
  echo "  DEFECTDOJO_ENGAGEMENT_ID"
  exit 0
fi

TRIVY_FS_REPORT="${TRIVY_FS_REPORT:-reports/trivy/trivy-fs-results.json}"
TRIVY_IMAGE_REPORT="${TRIVY_IMAGE_REPORT:-reports/trivy/trivy-image-results.json}"
SBOM_REPORT="${SBOM_REPORT:-reports/trivy/sbom/sbom-cyclonedx.json}"
ZAP_REPORT="${ZAP_REPORT:-reports/zap/report_json.json}"

if [[ "$DRY_RUN" == "false" ]]; then
  : "${DEFECTDOJO_URL:?DEFECTDOJO_URL não foi definido}"
  : "${DEFECTDOJO_TOKEN:?DEFECTDOJO_TOKEN não foi definido}"
  : "${DEFECTDOJO_ENGAGEMENT_ID:?DEFECTDOJO_ENGAGEMENT_ID não foi definido}"
fi

check_file() {
  local file_path="$1"
  local label="$2"

  if [[ -f "$file_path" ]]; then
    echo "[ok] $label encontrado em: $file_path"
    return 0
  fi

  echo "[aviso] $label não encontrado em: $file_path"
  return 1
}

import_scan() {
  local file_path="$1"
  local scan_type="$2"
  local test_title="$3"

  if [[ ! -f "$file_path" ]]; then
    echo "[skip] arquivo não encontrado, importação ignorada: $file_path"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] importaria '$file_path' como '$scan_type' com título '$test_title'"
    return 0
  fi

  echo "[import] enviando $file_path para o defectdojo como $scan_type"

  curl --fail --silent --show-error \
    --request POST "${DEFECTDOJO_URL%/}/api/v2/import-scan/" \
    --header "Authorization: Token ${DEFECTDOJO_TOKEN}" \
    --form "engagement=${DEFECTDOJO_ENGAGEMENT_ID}" \
    --form "scan_type=${scan_type}" \
    --form "file=@${file_path}" \
    --form "active=true" \
    --form "verified=true" \
    --form "close_old_findings=false" \
    --form "minimum_severity=Info" \
    --form "test_title=${test_title}"

  echo ""
  echo "[ok] importação concluída: $test_title"
}

echo "iniciando preparação de importação no defectdojo"
echo ""

check_file "$TRIVY_FS_REPORT" "relatório trivy fs" || true
check_file "$TRIVY_IMAGE_REPORT" "relatório trivy image" || true
check_file "$SBOM_REPORT" "sbom cyclonedx" || true
check_file "$ZAP_REPORT" "relatório zap" || true

echo ""
echo "iniciando importações"
echo ""

import_scan "$TRIVY_FS_REPORT" "Trivy Scan" "Trivy FS - análise de dependências"
import_scan "$TRIVY_IMAGE_REPORT" "Trivy Scan" "Trivy Image - análise da imagem docker"
import_scan "$SBOM_REPORT" "CycloneDX Scan" "SBOM CycloneDX"
import_scan "$ZAP_REPORT" "ZAP Scan" "OWASP ZAP - análise dinâmica"

echo ""
echo "processo finalizado"