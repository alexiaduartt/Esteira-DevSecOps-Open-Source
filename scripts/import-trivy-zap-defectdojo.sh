#!/usr/bin/env bash

set -euo pipefail

# Importa relatórios do Trivy, CycloneDX e OWASP ZAP no DefectDojo
# por meio da API REST de importação de scans.
# O script evita imprimir valores sensíveis nos logs e suporta modo de simulação.

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

json_escape() {
  local value="${1:-}"

  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"

  printf '%s' "$value"
}

write_log() {
  local component="$1"
  local status="$2"
  local scan_type="$3"
  local file_path="$4"
  local http_code="${5:-}"
  local details="${6:-}"
  local timestamp

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  printf '{"timestamp":"%s","component":"%s","status":"%s","scan_type":"%s","file":"%s"' \
    "$(json_escape "$timestamp")" \
    "$(json_escape "$component")" \
    "$(json_escape "$status")" \
    "$(json_escape "$scan_type")" \
    "$(json_escape "$file_path")" >> "$IMPORT_LOG"

  if [[ -n "$http_code" ]]; then
    printf ',"http_code":"%s"' "$(json_escape "$http_code")" >> "$IMPORT_LOG"
  fi

  if [[ -n "$details" ]]; then
    printf ',"details":"%s"' "$(json_escape "$details")" >> "$IMPORT_LOG"
  fi

  printf '}\n' >> "$IMPORT_LOG"
}

mask_sensitive_values() {
  if [[ "${GITHUB_ACTIONS:-false}" != "true" ]]; then
    return 0
  fi

  if [[ -n "$DEFECTDOJO_URL" ]]; then
    echo "::add-mask::$DEFECTDOJO_URL"
  fi

  if [[ -n "$DEFECTDOJO_TOKEN" ]]; then
    echo "::add-mask::$DEFECTDOJO_TOKEN"
  fi

  if [[ -n "$ENGAGEMENT_ID" ]]; then
    echo "::add-mask::$ENGAGEMENT_ID"
  fi
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
  log_detail "engagement_id=configured"

  local response_file
  local error_file

  response_file=$(mktemp)
  error_file=$(mktemp)

  local http_code
  local curl_exit

  set +e
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
    2> "$error_file")
  curl_exit=$?
  set -e

  local response_size
  local error_size

  response_size=$(wc -c < "$response_file" | tr -d '[:space:]')
  error_size=$(wc -c < "$error_file" | tr -d '[:space:]')

  rm -f "$response_file" "$error_file"

  if [[ "$curl_exit" -ne 0 ]]; then
    log "ERROR" "$component" \
      "Falha de comunicação com a API do DefectDojo."

    log_detail "curl_exit=$curl_exit"
    log_detail "response_body_bytes=$response_size"
    log_detail "stderr_bytes=$error_size"

    write_log \
      "$component" \
      "failed" \
      "$scan_type" \
      "$report_file" \
      "${http_code:-unknown}" \
      "curl_exit=$curl_exit response_body_bytes=$response_size stderr_bytes=$error_size"

    IMPORT_ERRORS=$((IMPORT_ERRORS + 1))
    return 0
  fi

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
  log_detail "response_body_bytes=$response_size"

  write_log \
    "$component" \
    "failed" \
    "$scan_type" \
    "$report_file" \
    "${http_code:-unknown}" \
    "response_body_bytes=$response_size"

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

mask_sensitive_values
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