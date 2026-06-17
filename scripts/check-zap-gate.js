/**
 * check-zap-gate.js
 * PBI-25 — Governança DAST
 *
 * Task 125 — Definir critérios de bloqueio da pipeline
 *
 * Lê o JSON de saída do OWASP ZAP, verifica se existem alertas de nível HIGH
 * (riskcode === 3). Se sim, encerra com process.exit(1), fazendo o job falhar.
 * Caso contrário, encerra com process.exit(0).
 *
 * Uso:
 *   node scripts/check-zap-gate.js [caminho/para/zap-report.json]
 *
 * Se nenhum caminho for informado, procura o JSON mais recente em reports/zap/.
 * Se o arquivo não existir (ZAP não rodou), loga um aviso e encerra com exit(0).
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const {
  classifyAlerts,
  groupByLevel,
  printSummary,
  findLatestZapReport,
} = require('./classify-zap-alerts');

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const inputArg      = process.argv[2];
  const zapReportPath = inputArg || findLatestZapReport();

  if (!zapReportPath) {
    console.warn('[AVISO] Nenhum relatório do OWASP ZAP encontrado em reports/zap/.');
    console.warn('        O ZAP ainda não foi executado nesta pipeline. Encerrando sem erro.');
    process.exit(0);
  }

  if (!fs.existsSync(zapReportPath)) {
    console.warn(`[AVISO] Arquivo do OWASP ZAP não encontrado: ${zapReportPath}`);
    console.warn('        O ZAP ainda não foi executado nesta pipeline. Encerrando sem erro.');
    process.exit(0);
  }

  console.log(`[INFO] Verificando quality gate DAST: ${zapReportPath}`);

  let zapJson;
  try {
    const raw = fs.readFileSync(zapReportPath, 'utf-8');
    zapJson = JSON.parse(raw);
  } catch (err) {
    console.error(`[ERRO] Falha ao ler/parsear o relatório ZAP: ${err.message}`);
    process.exit(1);
  }

  // Classificar e agrupar
  const classifiedAlerts = classifyAlerts(zapJson);
  const grouped          = groupByLevel(classifiedAlerts);

  // Exibir resumo
  printSummary(grouped);

  // Gate: verificar alertas HIGH
  const highCount = grouped.high.length;

  if (highCount > 0) {
    console.error('══════════════════════════════════════════════');
    console.error('  ❌ QUALITY GATE FALHOU — PIPELINE BLOQUEADA');
    console.error('══════════════════════════════════════════════');
    console.error(`  Encontrado(s) ${highCount} alerta(s) de severidade HIGH.`);
    console.error('  A pipeline não pode prosseguir com vulnerabilidades');
    console.error('  de alto risco não remediadas.');
    console.error('');
    console.error('  Alertas HIGH encontrados:');

    for (const alert of grouped.high) {
      console.error(`    • [${alert.alertRef || alert.pluginid}] ${alert.alert || alert.name}`);
      console.error(`      CWE: ${alert.cweid || 'N/A'} | ${alert.riskdesc || ''}`);
    }

    console.error('══════════════════════════════════════════════');
    process.exit(1);
  }

  console.log('══════════════════════════════════════════════');
  console.log('  ✅ QUALITY GATE APROVADO');
  console.log('══════════════════════════════════════════════');
  console.log('  Nenhum alerta de severidade HIGH encontrado.');
  console.log('  A pipeline pode prosseguir.');
  console.log('══════════════════════════════════════════════');
  process.exit(0);
}

main();
