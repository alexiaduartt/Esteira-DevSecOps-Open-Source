#!/usr/bin/env bash

set -euo pipefail

# Importa relatórios do Trivy, CycloneDX e OWASP ZAP no DefectDojo
# por meio da API REST de importação de scans.

DEFECTDOJO_URL="${DEFECTDOJO_URL:-}"
DEFECTDOJO_TOKEN="${DEFECTDOJO_TOKEN:-}"
ENGAGEMENT_ID="${ENGAGEMENT_ID:-}"

REPORTS_DIR="reports"
RESULTS_DIR="$REPORTS_DIR/defectdojo"

TRIVY_FS_REPORT="$REPORTS_DIR/trivy/trivy-fs-results.json"
TRIVY_IMAGE_REPORT="$REPORTS_DIR/trivy/trivy-image-results.json"
SBOM_REPORT="$REPORTS_DIR/trivy/sbom/sbom-cyclonedx.json"
ZAP_REPORT="$REPORTS_DIR/zap/report_json.json"

IMPORT_ENDPOINT="/api/v2/import-scan/"
IMPORT_LOG="$RESULTS_DIR/trivy-zap-import-log.jsonl"

DRY_RUN=false

IMPORT_SUCCESS=0
IMPORT_SIMULATED=0
IMPORT_SKIPPED=0
IMPORT_ERRORS=0

log() {
  local level="$1"
  local component="$2"
  local message="$3"

  printf '[%s] [%s] %s\n' "$level" "$component" "$message"
}

log_detail() {
  local message="$1"

  printf '       %s\n' "$message"
}

show_help() {
  cat <<'EOF'
Uso:
  bash scripts/import-trivy-zap-defectdojo.sh
  bash scripts/import-trivy-zap-defectdojo.sh --dry-run
  bash scripts/import-trivy-zap-defectdojo.sh --help

Variáveis obrigatórias para a importação real:
  DEFECTDOJO_URL
  DEFECTDOJO_TOKEN
  ENGAGEMENT_ID

Exemplo:
  export DEFECTDOJO_URL="http://localhost:8080"
  export DEFECTDOJO_TOKEN="token-da-api"
  export ENGAGEMENT_ID="1"

  bash scripts/import-trivy-zap-defectdojo.sh
EOF
}

validate_dependencies() {
  if ! command -v node > /dev/null 2>&1; then
    log "ERROR" "Dependências" \
      "O Node.js não está disponível no ambiente de execução."

    log_detail "Configure o Node.js antes de executar o script."
    exit 1
  fi

  if [[ "$DRY_RUN" == "false" ]] && ! command -v curl > /dev/null 2>&1; then
    log "ERROR" "Dependências" \
      "O cURL não está disponível no ambiente de execução."

    exit 1
  fi
}

validate_environment() {
  if [[ "$DRY_RUN" == "true" ]]; then
    return 0
  fi

  local missing_variables=0

  if [[ -z "$DEFECTDOJO_URL" ]]; then
    log "ERROR" "Configuração" \
      "A variável DEFECTDOJO_URL não foi definida."

    missing_variables=1
  fi

  if [[ -z "$DEFECTDOJO_TOKEN" ]]; then
    log "ERROR" "Configuração" \
      "A variável DEFECTDOJO_TOKEN não foi definida."

    missing_variables=1
  fi

  if [[ -z "$ENGAGEMENT_ID" ]]; then
    log "ERROR" "Configuração" \
      "A variável ENGAGEMENT_ID não foi definida."

    missing_variables=1
  fi

  if [[ "$missing_variables" -ne 0 ]]; then
    log "INFO" "Configuração" \
      "Utilize --help para consultar as variáveis obrigatórias."

    exit 1
  fi
}

write_log() {
  local component="$1"
  local status="$2"
  local scan_type="$3"
  local file_path="$4"
  local http_code="${5:-}"
  local details="${6:-}"

  COMPONENT="$component" \
  STATUS="$status" \
  SCAN_TYPE="$scan_type" \
  FILE_PATH="$file_path" \
  HTTP_CODE="$http_code" \
  DETAILS="$details" \
  node <<'NODE' >> "$IMPORT_LOG"
const entry = {
  timestamp: new Date().toISOString(),
  component: process.env.COMPONENT,
  status: process.env.STATUS,
  scan_type: process.env.SCAN_TYPE,
  file: process.env.FILE_PATH,
};

const httpCode = process.env.HTTP_CODE;
const details = process.env.DETAILS;

if (httpCode) {
  entry.http_code = httpCode;
}

if (details) {
  entry.details = details;
}

process.stdout.write(`${JSON.stringify(entry)}\n`);
NODE
}

import_scan() {
  local component="$1"
  local scan_type="$2"
  local report_file="$3"
  local test_title="$4"

  if [[ ! -f "$report_file" ]]; then
    log "WARN" "$component" "Relatório não encontrado."
    log_detail "path=$report_file"

    write_log \
      "$component" \
      "skipped" \
      "$scan_type" \
      "$report_file" \
      "" \
      "file_not_found"

    IMPORT_SKIPPED=$((IMPORT_SKIPPED + 1))
    return 0
  fi

  if [[ ! -s "$report_file" ]]; then
    log "ERROR" "$component" "O relatório está vazio."
    log_detail "path=$report_file"

    write_log \
      "$component" \
      "failed" \
      "$scan_type" \
      "$report_file" \
      "" \
      "empty_file"

    IMPORT_ERRORS=$((IMPORT_ERRORS + 1))
    return 0
  fi

  local file_size
  file_size=$(wc -c < "$report_file" | tr -d '[:space:]')

  if [[ "$DRY_RUN" == "true" ]]; then
    log "OK" "$component" \
      "Relatório preparado para importação em modo de simulação."

    log_detail "path=$report_file"
    log_detail "scan_type=$scan_type"
    log_detail "size_bytes=$file_size"

    write_log \
      "$component" \
      "simulated" \
      "$scan_type" \
      "$report_file" \
      "" \
      "Importação não executada em modo de simulação."

    IMPORT_SIMULATED=$((IMPORT_SIMULATED + 1))
    return 0
  fi

  log "INFO" "$component" \
    "Iniciando importação no DefectDojo."

  log_detail "path=$report_file"
  log_detail "scan_type=$scan_type"
  log_detail "size_bytes=$file_size"
  log_detail "engagement_id=$ENGAGEMENT_ID"

  local response_file
  response_file=$(mktemp)

  local http_code
  http_code=$(curl \
    --silent \
    --show-error \
    --output "$response_file" \
    --write-out "%{http_code}" \
    --request POST \
    "${DEFECTDOJO_URL%/}${IMPORT_ENDPOINT}" \
    --header "Authorization: Token ${DEFECTDOJO_TOKEN}" \
    --form "scan_type=${scan_type}" \
    --form "file=@${report_file}" \
    --form "engagement=${ENGAGEMENT_ID}" \
    --form "active=true" \
    --form "verified=false" \
    --form "close_old_findings=false" \
    --form "minimum_severity=Info" \
    --form "test_title=${test_title}" \
    || true)

  local response_body
  response_body=$(cat "$response_file")

  rm -f "$response_file"

  if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
    log "OK" "$component" \
      "Importação concluída com sucesso."

    log_detail "http_status=$http_code"

    write_log \
      "$component" \
      "success" \
      "$scan_type" \
      "$report_file" \
      "$http_code"

    IMPORT_SUCCESS=$((IMPORT_SUCCESS + 1))
    return 0
  fi

  log "ERROR" "$component" \
    "A API do DefectDojo rejeitou a importação."

  log_detail "http_status=${http_code:-unknown}"

  if [[ -n "$response_body" ]]; then
    log_detail "response=$response_body"
  fi

  write_log \
    "$component" \
    "failed" \
    "$scan_type" \
    "$report_file" \
    "${http_code:-unknown}" \
    "$response_body"

  IMPORT_ERRORS=$((IMPORT_ERRORS + 1))
}

case "${1:-}" in
  "--dry-run")
    DRY_RUN=true
    ;;
  "--help"|"-h")
    show_help
    exit 0
    ;;
  "")
    ;;
  *)
    log "ERROR" "Execução" "Parâmetro inválido: ${1}"
    show_help
    exit 1
    ;;
esac

validate_dependencies
validate_environment

mkdir -p "$RESULTS_DIR"
: > "$IMPORT_LOG"

log "INFO" "DefectDojo" \
  "Iniciando processamento dos relatórios de segurança."

if [[ "$DRY_RUN" == "true" ]]; then
  log "INFO" "DefectDojo" \
    "Modo de simulação ativado. Nenhum relatório será enviado."
fi

echo ""

import_scan \
  "Trivy FS" \
  "Trivy Scan" \
  "$TRIVY_FS_REPORT" \
  "Trivy FS - Análise do Sistema de Arquivos"

import_scan \
  "Trivy Image" \
  "Trivy Scan" \
  "$TRIVY_IMAGE_REPORT" \
  "Trivy Image - Análise da Imagem Docker"

import_scan \
  "CycloneDX" \
  "CycloneDX Scan" \
  "$SBOM_REPORT" \
  "SBOM CycloneDX - Componentes da Aplicação"

import_scan \
  "OWASP ZAP" \
  "ZAP Scan" \
  "$ZAP_REPORT" \
  "OWASP ZAP - Análise Dinâmica de Segurança"

echo ""

if [[ "$IMPORT_ERRORS" -gt 0 ]]; then
  log "SUMMARY" "DefectDojo" \
    "status=failed success=$IMPORT_SUCCESS simulated=$IMPORT_SIMULATED skipped=$IMPORT_SKIPPED errors=$IMPORT_ERRORS"

  log "ERROR" "DefectDojo" \
    "Uma ou mais importações apresentaram erro."

  exit 1
fi

if [[ "$IMPORT_SKIPPED" -gt 0 ]]; then
  log "SUMMARY" "DefectDojo" \
    "status=completed_with_warnings success=$IMPORT_SUCCESS simulated=$IMPORT_SIMULATED skipped=$IMPORT_SKIPPED errors=$IMPORT_ERRORS"

  log "INFO" "DefectDojo" \
    "Os relatórios ausentes podem ser gerados durante a execução da pipeline."

  exit 0
fi

if [[ "$DRY_RUN" == "true" ]]; then
  log "SUMMARY" "DefectDojo" \
    "status=simulation_completed success=$IMPORT_SUCCESS simulated=$IMPORT_SIMULATED skipped=$IMPORT_SKIPPED errors=$IMPORT_ERRORS"

  log "INFO" "DefectDojo" \
    "A simulação foi concluída sem envio de dados."

  exit 0
fi

log "SUMMARY" "DefectDojo" \
  "status=success success=$IMPORT_SUCCESS simulated=$IMPORT_SIMULATED skipped=$IMPORT_SKIPPED errors=$IMPORT_ERRORS"

log "INFO" "DefectDojo" \
  "Todos os relatórios disponíveis foram processados."

exit 0