#!/bin/bash
# =============================================================================
# validate-defectdojo-compatibility.sh
# PBI-28 / Task 139 — Garantir relatórios compatíveis com DefectDojo
#
# Verifica se os relatórios gerados pelo Semgrep e GitLeaks estão em formatos
# aceitos nativamente pelo DefectDojo:
#   - Semgrep  → scan_type "Semgrep JSON Report" (campo "results" obrigatório)
#   - GitLeaks → scan_type "Gitleaks Scan"       (array JSON de findings)
#
# Uso:
#   bash scripts/validate-defectdojo-compatibility.sh
# =============================================================================

set -euo pipefail

REPORTS_DIR="reports"
SEMGREP_REPORT="$REPORTS_DIR/semgrep/semgrep-results.json"
GITLEAKS_REPORT="$REPORTS_DIR/gitleaks/gitleaks-results.json"

ERRORS=0
WARNINGS=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_ok()   { echo "  ✅ $1"; }
log_warn() { echo "  ⚠️  $1"; WARNINGS=$((WARNINGS + 1)); }
log_err()  { echo "  ❌ $1"; ERRORS=$((ERRORS + 1)); }

validate_json() {
  local file="$1"
  if python3 -m json.tool "$file" > /dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Validação do Semgrep
# ---------------------------------------------------------------------------

echo "══════════════════════════════════════════════════════════════"
echo "  PBI-28 │ Validação de Compatibilidade com DefectDojo"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "── Semgrep (scan_type: Semgrep JSON Report) ──"

if [ ! -f "$SEMGREP_REPORT" ]; then
  log_warn "Relatório Semgrep não encontrado: $SEMGREP_REPORT"
  log_warn "O Semgrep pode não ter sido executado nesta pipeline."
else
  # 1. Verificar se é JSON válido
  if validate_json "$SEMGREP_REPORT"; then
    log_ok "JSON válido"
  else
    log_err "JSON inválido — $SEMGREP_REPORT"
  fi

  # 2. Verificar tamanho do arquivo
  SIZE=$(stat -c%s "$SEMGREP_REPORT" 2>/dev/null || stat -f%z "$SEMGREP_REPORT" 2>/dev/null || echo "0")
  if [ "$SIZE" -gt 0 ]; then
    log_ok "Arquivo não vazio ($SIZE bytes)"
  else
    log_err "Arquivo vazio — $SEMGREP_REPORT"
  fi

  # 3. Verificar campo "results" (obrigatório para o DefectDojo)
  if python3 -c "
import json, sys
with open('$SEMGREP_REPORT') as f:
    data = json.load(f)
if 'results' not in data:
    sys.exit(1)
print(f'  Findings encontrados: {len(data[\"results\"])}')
" 2>/dev/null; then
    log_ok "Campo 'results' presente (formato Semgrep JSON Report)"
  else
    log_err "Campo 'results' ausente — DefectDojo requer este campo para 'Semgrep JSON Report'"
  fi

  # 4. Verificar campos dos findings (se houver)
  python3 -c "
import json
with open('$SEMGREP_REPORT') as f:
    data = json.load(f)
results = data.get('results', [])
if results:
    sample = results[0]
    required = ['check_id', 'path', 'start', 'end', 'extra']
    missing = [k for k in required if k not in sample]
    if missing:
        print(f'  ⚠️  Campos faltando no primeiro finding: {missing}')
    else:
        print(f'  ✅ Campos essenciais presentes nos findings (check_id, path, start, end, extra)')
    severity = sample.get('extra', {}).get('severity', 'N/A')
    print(f'  ℹ️  Severidade do primeiro finding: {severity}')
else:
    print('  ℹ️  Nenhum finding Semgrep — relatório limpo')
" 2>/dev/null || true
fi

echo ""

# ---------------------------------------------------------------------------
# Validação do GitLeaks
# ---------------------------------------------------------------------------

echo "── GitLeaks (scan_type: Gitleaks Scan) ──"

if [ ! -f "$GITLEAKS_REPORT" ]; then
  log_warn "Relatório GitLeaks não encontrado: $GITLEAKS_REPORT"
  log_warn "O GitLeaks pode não ter sido executado nesta pipeline."
else
  # 1. Verificar se é JSON válido
  if validate_json "$GITLEAKS_REPORT"; then
    log_ok "JSON válido"
  else
    log_err "JSON inválido — $GITLEAKS_REPORT"
  fi

  # 2. Verificar tamanho do arquivo
  SIZE=$(stat -c%s "$GITLEAKS_REPORT" 2>/dev/null || stat -f%z "$GITLEAKS_REPORT" 2>/dev/null || echo "0")
  if [ "$SIZE" -gt 0 ]; then
    log_ok "Arquivo não vazio ($SIZE bytes)"
  else
    log_err "Arquivo vazio — $GITLEAKS_REPORT"
  fi

  # 3. Verificar que é um array JSON (formato GitLeaks)
  if python3 -c "
import json, sys
with open('$GITLEAKS_REPORT') as f:
    data = json.load(f)
if isinstance(data, list):
    print(f'  Findings encontrados: {len(data)}')
    sys.exit(0)
else:
    sys.exit(1)
" 2>/dev/null; then
    log_ok "Formato correto: array JSON (compatível com Gitleaks Scan)"
  else
    log_err "Formato incorreto — DefectDojo espera um array JSON para 'Gitleaks Scan'"
  fi

  # 4. Verificar campos dos findings (se houver)
  python3 -c "
import json
with open('$GITLEAKS_REPORT') as f:
    data = json.load(f)
if isinstance(data, list) and data:
    sample = data[0]
    required = ['RuleID', 'File', 'StartLine']
    missing = [k for k in required if k not in sample]
    if missing:
        print(f'  ⚠️  Campos faltando no primeiro finding: {missing}')
    else:
        print(f'  ✅ Campos essenciais presentes nos findings (RuleID, File, StartLine)')
    rule = sample.get('RuleID', 'N/A')
    print(f'  ℹ️  Regra do primeiro finding: {rule}')
elif isinstance(data, list) and not data:
    print('  ℹ️  Nenhum finding GitLeaks — relatório limpo (sem secrets vazados)')
" 2>/dev/null || true
fi

echo ""

# ---------------------------------------------------------------------------
# Resumo Final
# ---------------------------------------------------------------------------

echo "══════════════════════════════════════════════════════════════"
echo "  Resumo de Compatibilidade"
echo "══════════════════════════════════════════════════════════════"
echo "  Erros:   $ERRORS"
echo "  Avisos:  $WARNINGS"

if [ $ERRORS -gt 0 ]; then
  echo ""
  echo "  ❌ Validação FALHOU — relatórios incompatíveis com DefectDojo"
  echo "══════════════════════════════════════════════════════════════"
  exit 1
fi

if [ $WARNINGS -gt 0 ]; then
  echo ""
  echo "  ⚠️  Validação OK com avisos — verifique se os relatórios serão gerados na pipeline"
  echo "══════════════════════════════════════════════════════════════"
  exit 0
fi

echo ""
echo "  ✅ Todos os relatórios estão compatíveis com o DefectDojo"
echo "══════════════════════════════════════════════════════════════"
exit 0
