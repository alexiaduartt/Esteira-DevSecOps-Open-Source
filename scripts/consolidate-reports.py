#!/usr/bin/env python3
"""
Consolidação de relatórios SCA (Trivy FS + Trivy Image).
PBI-20 / Tasks #100, #101, #102

Gera um relatório unificado com:
- Resumo de vulnerabilidades por severidade e origem
- Lista de CVEs agrupadas por nível de severidade
- Instruções de importação para o DefectDojo
"""

import json
import os
import sys
from datetime import datetime, timezone

# --- Configuração ---
REPORTS_DIR = "reports/trivy"
FS_REPORT = os.path.join(REPORTS_DIR, "trivy-fs-results.json")
IMAGE_REPORT = os.path.join(REPORTS_DIR, "trivy-image-results.json")
OUTPUT_REPORT = os.path.join(REPORTS_DIR, "consolidated-report.json")
DEFECTDOJO_SCRIPT = os.path.join(REPORTS_DIR, "defectdojo-import.sh")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Conforme security/policies/dependency-severity-policy.md
SEVERITY_POLICY = {
    "CRITICAL": "bloqueio",
    "HIGH": "bloqueio",
    "MEDIUM": "alerta",
    "LOW": "alerta",
    "UNKNOWN": "alerta",
}


def load_json(filepath):
    """Carrega um arquivo JSON. Retorna None se não existir."""
    if not os.path.isfile(filepath):
        print(f"  Aviso: arquivo não encontrado — {filepath}")
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_vulnerabilities(report_data, source_name):
    """
    Extrai vulnerabilidades de um relatório Trivy JSON.
    Retorna lista de dicts com campos resumidos.
    """
    vulns = []
    if report_data is None:
        return vulns

    results = report_data.get("Results", [])
    for result in results:
        target = result.get("Target", "unknown")
        target_type = result.get("Type", "unknown")
        for vuln in result.get("Vulnerabilities", []):
            vulns.append({
                "id": vuln.get("VulnerabilityID", "N/A"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "package": vuln.get("PkgName", "N/A"),
                "installed_version": vuln.get("InstalledVersion", "N/A"),
                "fixed_version": vuln.get("FixedVersion", ""),
                "title": vuln.get("Title", ""),
                "source": source_name,
                "target": target,
                "target_type": target_type,
                "policy_action": SEVERITY_POLICY.get(
                    vuln.get("Severity", "UNKNOWN"), "alerta"
                ),
            })
    return vulns


def group_by_severity(vulns):
    """Agrupa vulnerabilidades por nível de severidade."""
    grouped = {sev: [] for sev in SEVERITY_ORDER}
    for vuln in vulns:
        severity = vuln.get("severity", "UNKNOWN")
        if severity not in grouped:
            severity = "UNKNOWN"
        grouped[severity].append(vuln)
    return grouped


def build_summary(grouped, all_vulns):
    """Gera o resumo com contagens e status de bloqueio."""
    by_severity = {sev: len(items) for sev, items in grouped.items() if items}
    by_source = {}
    for vuln in all_vulns:
        src = vuln["source"]
        by_source[src] = by_source.get(src, 0) + 1

    has_blocking = any(
        vuln["policy_action"] == "bloqueio" for vuln in all_vulns
    )

    return {
        "total_vulnerabilities": len(all_vulns),
        "by_severity": by_severity,
        "by_source": by_source,
        "pipeline_blocked": has_blocking,
        "policy_reference": "security/policies/dependency-severity-policy.md",
    }


def build_defectdojo_section():
    """Gera seção com instruções de importação para o DefectDojo."""
    return {
        "import_instructions": (
            "O DefectDojo aceita Trivy JSON nativamente via scan_type 'Trivy Scan'. "
            "Recomenda-se importar cada scan como um Test separado dentro do mesmo "
            "Engagement. Use o script defectdojo-import.sh gerado como template."
        ),
        "scan_type": "Trivy Scan",
        "files": [
            {
                "source": "trivy-fs",
                "file": "trivy-fs-results.json",
                "test_name": "Trivy FS Scan - Dependências npm",
            },
            {
                "source": "trivy-image",
                "file": "trivy-image-results.json",
                "test_name": "Trivy Image Scan - Imagem Docker",
            },
        ],
    }


def generate_defectdojo_script():
    """Gera script shell template para importação no DefectDojo."""
    return """#!/bin/bash
# Template de importação para DefectDojo
# PBI-20 / Task #102
#
# Preencha as variáveis abaixo com os dados do seu ambiente.
# Este script NÃO é executado automaticamente na pipeline.

DEFECTDOJO_URL="https://<seu-defectdojo>/api/v2/import-scan/"
API_TOKEN="<seu-token>"
ENGAGEMENT_ID="<id-do-engagement>"

echo "== Importando Trivy FS Scan =="
curl -X POST "$DEFECTDOJO_URL" \\
     -H "Authorization: Token $API_TOKEN" \\
     -F "scan_type=Trivy Scan" \\
     -F "file=@reports/trivy/trivy-fs-results.json" \\
     -F "engagement=$ENGAGEMENT_ID" \\
     -F "active=true" \\
     -F "verified=false" \\
     -F "test_title=Trivy FS Scan - Dependências npm"

echo ""
echo "== Importando Trivy Image Scan =="
curl -X POST "$DEFECTDOJO_URL" \\
     -H "Authorization: Token $API_TOKEN" \\
     -F "scan_type=Trivy Scan" \\
     -F "file=@reports/trivy/trivy-image-results.json" \\
     -F "engagement=$ENGAGEMENT_ID" \\
     -F "active=true" \\
     -F "verified=false" \\
     -F "test_title=Trivy Image Scan - Imagem Docker"

echo ""
echo "Importação concluída."
"""


def main():
    print("=== PBI-20: Consolidação de Relatórios SCA ===")
    print()

    # Garante que a pasta reports/trivy exista logo no início
    os.makedirs(REPORTS_DIR, exist_ok=True)


    # Task #100 — Carregar relatórios
    print("[Task #100] Carregando relatórios...")
    fs_data = load_json(FS_REPORT)
    image_data = load_json(IMAGE_REPORT)

    if fs_data is None and image_data is None:
        print("ERRO: Nenhum relatório Trivy encontrado.")
        sys.exit(1)

    # Extrair vulnerabilidades
    fs_vulns = extract_vulnerabilities(fs_data, "trivy-fs")
    image_vulns = extract_vulnerabilities(image_data, "trivy-image")
    all_vulns = fs_vulns + image_vulns

    print(f"  Trivy FS: {len(fs_vulns)} vulnerabilidade(s)")
    print(f"  Trivy Image: {len(image_vulns)} vulnerabilidade(s)")
    print(f"  Total: {len(all_vulns)} vulnerabilidade(s)")
    print()

    # Task #101 — Separar por severidade
    print("[Task #101] Agrupando por severidade...")
    grouped = group_by_severity(all_vulns)
    for sev in SEVERITY_ORDER:
        count = len(grouped[sev])
        if count > 0:
            action = SEVERITY_POLICY.get(sev, "alerta")
            print(f"  {sev}: {count} ({action})")
    print()

    # Construir relatório consolidado
    summary = build_summary(grouped, all_vulns)

    # Limpar grupos vazios para o output
    vulns_output = {
        sev: items for sev, items in grouped.items() if items
    }

    consolidated = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "commit_sha": os.environ.get("COMMIT_SHA", "local"),
            "run_id": os.environ.get("RUN_ID", "local"),
            "run_number": os.environ.get("RUN_NUMBER", "local"),
            "sources": [],
        },
        "summary": summary,
        "vulnerabilities": vulns_output,
        "defectdojo": build_defectdojo_section(),
    }

    if fs_data is not None:
        consolidated["metadata"]["sources"].append("trivy-fs")
    if image_data is not None:
        consolidated["metadata"]["sources"].append("trivy-image")

    # Salvar relatório consolidado
    os.makedirs(os.path.dirname(OUTPUT_REPORT), exist_ok=True)
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(consolidated, f, indent=2, ensure_ascii=False)
    print(f"[Task #100] Relatório consolidado salvo: {OUTPUT_REPORT}")

    # Task #102 — Template DefectDojo
    print("[Task #102] Gerando template de importação DefectDojo...")
    with open(DEFECTDOJO_SCRIPT, "w", encoding="utf-8") as f:
        f.write(generate_defectdojo_script())
    os.chmod(DEFECTDOJO_SCRIPT, 0o755)
    print(f"  Template salvo: {DEFECTDOJO_SCRIPT}")
    print()

    # Resumo final
    if summary["pipeline_blocked"]:
        print("RESULTADO: Pipeline BLOQUEADA — vulnerabilidades HIGH/CRITICAL encontradas")
    else:
        print("RESULTADO: Nenhuma vulnerabilidade de bloqueio encontrada")

    print(f"Total: {summary['total_vulnerabilities']} vulnerabilidade(s)")
    print("Consolidação concluída com sucesso.")


if __name__ == "__main__":
    main()
