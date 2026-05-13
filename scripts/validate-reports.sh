#!/bin/bash
# Validação de integridade dos relatórios de segurança
# PBI-14 / Task #73

set -euo pipefail

REPORT_DIR="reports"
ERRORS=0

for tool_dir in "$REPORT_DIR"/gitleaks "$REPORT_DIR"/semgrep; do
  TOOL=$(basename "$tool_dir")
  echo "Validando relatórios de $TOOL"

  json_files=$(find "$tool_dir" -name "*.json" -not -name ".gitkeep" 2>/dev/null)

  if [ -z "$json_files" ]; then
    echo "ERRO: Nenhum relatório encontrado em $tool_dir"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  for file in $json_files; do
    if [ ! -s "$file" ]; then
      echo "ERRO: Arquivo vazio — $file"
      ERRORS=$((ERRORS + 1))
      continue
    fi

    if python3 -m json.tool "$file" > /dev/null 2>&1; then
      SIZE=$(stat -c%s "$file")
      echo "OK: $file ($SIZE bytes)"
    else
      echo "ERRO: JSON inválido — $file"
      ERRORS=$((ERRORS + 1))
    fi
  done
done

if [ $ERRORS -gt 0 ]; then
  echo ""
  echo "Validação falhou com $ERRORS erro(s)."
  exit 1
fi

echo ""
echo "Todos os relatórios estão válidos."
exit 0
