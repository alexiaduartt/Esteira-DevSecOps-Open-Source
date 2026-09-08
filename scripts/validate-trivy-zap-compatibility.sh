#!/usr/bin/env bash

set -euo pipefail

# Valida a estrutura dos relatórios do Trivy, CycloneDX e OWASP ZAP
# antes da importação nos parsers correspondentes do DefectDojo.

REPORTS_DIR="reports"

TRIVY_FS_REPORT="$REPORTS_DIR/trivy/trivy-fs-results.json"
TRIVY_IMAGE_REPORT="$REPORTS_DIR/trivy/trivy-image-results.json"
SBOM_REPORT="$REPORTS_DIR/trivy/sbom/sbom-cyclonedx.json"
ZAP_REPORT="$REPORTS_DIR/zap/report_json.json"

ERRORS=0
WARNINGS=0

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

register_warning() {
  WARNINGS=$((WARNINGS + 1))
}

register_error() {
  ERRORS=$((ERRORS + 1))
}

validate_dependencies() {
  if ! command -v node > /dev/null 2>&1; then
    log "ERROR" "Dependências" \
      "O Node.js não está disponível no ambiente de execução."

    exit 1
  fi
}

validate_json() {
  local file_path="$1"

  REPORT_FILE="$file_path" node -e '
    const fs = require("fs");

    const content = fs.readFileSync(
      process.env.REPORT_FILE,
      "utf8"
    );

    JSON.parse(content);
  ' > /dev/null 2>&1
}

validate_file() {
  local file_path="$1"
  local component="$2"
  local description="$3"

  if [[ ! -f "$file_path" ]]; then
    log "WARN" "$component" "$description não encontrado."
    log_detail "path=$file_path"
    register_warning
    return 1
  fi

  if [[ ! -s "$file_path" ]]; then
    log "ERROR" "$component" "$description está vazio."
    log_detail "path=$file_path"
    register_error
    return 1
  fi

  if ! validate_json "$file_path"; then
    log "ERROR" "$component" \
      "$description não contém um JSON válido."

    log_detail "path=$file_path"
    register_error
    return 1
  fi

  return 0
}

print_metrics() {
  local metrics="$1"

  while IFS= read -r metric; do
    if [[ -n "$metric" ]]; then
      log_detail "$metric"
    fi
  done <<< "$metrics"
}

validate_trivy_report() {
  local file_path="$1"
  local component="$2"

  if ! validate_file "$file_path" "$component" "Relatório"; then
    return
  fi

  local metrics

  if metrics=$(REPORT_FILE="$file_path" node <<'NODE'
const fs = require('fs');

const data = JSON.parse(
  fs.readFileSync(process.env.REPORT_FILE, 'utf8')
);

if (!Array.isArray(data.Results)) {
  process.stdout.write('missing_field=Results\n');
  process.exit(1);
}

const vulnerabilities = data.Results.flatMap((result) => {
  return Array.isArray(result.Vulnerabilities)
    ? result.Vulnerabilities
    : [];
});

const requiredFields = [
  'VulnerabilityID',
  'PkgName',
  'InstalledVersion',
  'Severity',
];

let invalidFindings = 0;
const missingFields = new Set();

for (const vulnerability of vulnerabilities) {
  for (const field of requiredFields) {
    if (!(field in vulnerability)) {
      invalidFindings += 1;
      missingFields.add(field);
    }
  }
}

process.stdout.write(`results=${data.Results.length}\n`);
process.stdout.write(
  `vulnerabilities=${vulnerabilities.length}\n`
);

if (invalidFindings > 0) {
  process.stdout.write(
    `invalid_fields=${Array.from(missingFields).join(',')}\n`
  );

  process.exit(2);
}
NODE
  ); then
    log "OK" "$component" \
      "Relatório compatível com o parser Trivy Scan."

    print_metrics "$metrics"
  else
    log "ERROR" "$component" \
      "Estrutura incompatível com o parser Trivy Scan."

    if [[ -n "${metrics:-}" ]]; then
      print_metrics "$metrics"
    fi

    register_error
  fi
}

validate_sbom_report() {
  local component="CycloneDX"

  if ! validate_file "$SBOM_REPORT" "$component" "SBOM"; then
    return
  fi

  local metrics

  if metrics=$(REPORT_FILE="$SBOM_REPORT" node <<'NODE'
const fs = require('fs');

const data = JSON.parse(
  fs.readFileSync(process.env.REPORT_FILE, 'utf8')
);

if (data.bomFormat !== 'CycloneDX') {
  process.stdout.write(
    `invalid_bom_format=${data.bomFormat || 'undefined'}\n`
  );

  process.exit(1);
}

if (!Array.isArray(data.components)) {
  process.stdout.write('missing_field=components\n');
  process.exit(1);
}

process.stdout.write(
  `specification=${data.specVersion || 'unknown'}\n`
);

process.stdout.write(
  `components=${data.components.length}\n`
);

if (Array.isArray(data.vulnerabilities)) {
  process.stdout.write(
    `vulnerabilities=${data.vulnerabilities.length}\n`
  );
}
NODE
  ); then
    log "OK" "$component" \
      "SBOM compatível com o parser CycloneDX Scan."

    print_metrics "$metrics"
  else
    log "ERROR" "$component" \
      "Estrutura incompatível com o parser CycloneDX Scan."

    if [[ -n "${metrics:-}" ]]; then
      print_metrics "$metrics"
    fi

    register_error
  fi
}

validate_zap_report() {
  local component="OWASP ZAP"

  if ! validate_file "$ZAP_REPORT" "$component" "Relatório"; then
    return
  fi

  local metrics

  if metrics=$(REPORT_FILE="$ZAP_REPORT" node <<'NODE'
const fs = require('fs');

const data = JSON.parse(
  fs.readFileSync(process.env.REPORT_FILE, 'utf8')
);

if (!Array.isArray(data.site)) {
  process.stdout.write('missing_field=site\n');
  process.exit(1);
}

const alerts = data.site.flatMap((site) => {
  return Array.isArray(site.alerts)
    ? site.alerts
    : [];
});

const requiredFields = [
  'alert',
  'riskcode',
  'riskdesc',
];

let invalidAlerts = 0;
const missingFields = new Set();

for (const alert of alerts) {
  for (const field of requiredFields) {
    if (!(field in alert)) {
      invalidAlerts += 1;
      missingFields.add(field);
    }
  }
}

process.stdout.write(`sites=${data.site.length}\n`);
process.stdout.write(`alerts=${alerts.length}\n`);

if (invalidAlerts > 0) {
  process.stdout.write(
    `invalid_fields=${Array.from(missingFields).join(',')}\n`
  );

  process.exit(2);
}
NODE
  ); then
    log "OK" "$component" \
      "Relatório compatível com o parser ZAP Scan."

    print_metrics "$metrics"
  else
    log "ERROR" "$component" \
      "Estrutura incompatível com o parser ZAP Scan."

    if [[ -n "${metrics:-}" ]]; then
      print_metrics "$metrics"
    fi

    register_error
  fi
}

validate_dependencies

log "INFO" "DefectDojo" \
  "Iniciando validação de compatibilidade dos relatórios."

echo ""

validate_trivy_report \
  "$TRIVY_FS_REPORT" \
  "Trivy FS"

validate_trivy_report \
  "$TRIVY_IMAGE_REPORT" \
  "Trivy Image"

validate_sbom_report
validate_zap_report

echo ""

if [[ "$ERRORS" -gt 0 ]]; then
  log "SUMMARY" "DefectDojo" \
    "status=failed errors=$ERRORS warnings=$WARNINGS"

  log "ERROR" "DefectDojo" \
    "A validação identificou relatórios incompatíveis."

  exit 1
fi

if [[ "$WARNINGS" -gt 0 ]]; then
  log "SUMMARY" "DefectDojo" \
    "status=completed_with_warnings errors=$ERRORS warnings=$WARNINGS"

  log "INFO" "DefectDojo" \
    "Os relatórios ausentes podem ser gerados somente durante a execução da pipeline."

  exit 0
fi

log "SUMMARY" "DefectDojo" \
  "status=success errors=$ERRORS warnings=$WARNINGS"

log "INFO" "DefectDojo" \
  "Todos os relatórios estão compatíveis com os parsers configurados."

exit 0