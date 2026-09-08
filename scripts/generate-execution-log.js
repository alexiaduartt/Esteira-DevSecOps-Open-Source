/**
 * generate-execution-log.js
 * PBI-59 / Task 330 — Gerar Log Unificado de Execução
 *
 * Consolida os resultados de todos os scans e do quality gate
 * em um log unificado de execução da esteira.
 *
 * Uso: node scripts/generate-execution-log.js
 * Saída: reports/quality-gate/execution-log.json
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const ROOT_DIR    = path.resolve(__dirname, '..');
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');
const OUTPUT_DIR  = path.join(REPORTS_DIR, 'quality-gate');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'execution-log.json');

const REPORT_FILES = {
  'Semgrep (SAST)':   path.join(REPORTS_DIR, 'semgrep', 'semgrep-results.json'),
  'Gitleaks (Secrets)': path.join(REPORTS_DIR, 'gitleaks', 'gitleaks-results.json'),
  'Trivy FS (SCA)':   path.join(REPORTS_DIR, 'trivy', 'trivy-fs-results.json'),
  'Trivy Image (SCA)': path.join(REPORTS_DIR, 'trivy', 'trivy-image-results.json'),
  'Quality Gate':     path.join(OUTPUT_DIR, 'quality-gate-report.json'),
};

const VALIDATION_REPORTS = {
  'Findings Validation':     path.join(REPORTS_DIR, 'defectdojo', 'findings-validation.json'),
  'Trivy ZAP Validation':    path.join(REPORTS_DIR, 'defectdojo', 'trivy-zap-findings-validation.json'),
};

function getFileStatus(filepath) {
  if (!fs.existsSync(filepath)) return { exists: false, size: 0, status: 'missing' };
  const stat = fs.statSync(filepath);
  if (stat.size === 0) return { exists: true, size: 0, status: 'empty' };
  try {
    JSON.parse(fs.readFileSync(filepath, 'utf-8'));
    return { exists: true, size: stat.size, status: 'valid' };
  } catch {
    return { exists: true, size: stat.size, status: 'invalid_json' };
  }
}

function loadJsonSafe(filepath) {
  try {
    if (!fs.existsSync(filepath)) return null;
    return JSON.parse(fs.readFileSync(filepath, 'utf-8'));
  } catch {
    return null;
  }
}

function countFindings(tool, data) {
  if (!data) return 0;

  if (tool.includes('Semgrep')) {
    return Array.isArray(data.results) ? data.results.length : 0;
  }
  if (tool.includes('Gitleaks')) {
    return Array.isArray(data) ? data.length : 0;
  }
  if (tool.includes('Trivy')) {
    if (!Array.isArray(data.Results)) return 0;
    let count = 0;
    for (const r of data.Results) {
      count += Array.isArray(r.Vulnerabilities) ? r.Vulnerabilities.length : 0;
    }
    return count;
  }
  return 0;
}

function main() {
  const startTime = Date.now();

  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('  PBI-59 │ Log Unificado de Execução');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('');

  const executionLog = {
    metadata: {
      pbi: 'PBI-59',
      task: 'Task 330',
      description: 'Log Unificado de Execução da Esteira DevSecOps',
      generated_at: new Date().toISOString(),
      commit: process.env.COMMIT_SHA || process.env.GITHUB_SHA || 'local',
      run_id: process.env.RUN_ID || process.env.GITHUB_RUN_ID || 'local',
      branch: process.env.BRANCH_NAME || process.env.GITHUB_REF_NAME || 'local',
    },
    scan_reports: [],
    validation_reports: [],
    quality_gate: null,
    summary: {
      total_scans: 0,
      scans_with_findings: 0,
      scans_missing: 0,
      total_findings: 0,
      gate_decision: 'UNKNOWN',
    },
  };

  // Processar relatórios de scan
  console.log('  📋 Relatórios de Scan:');
  for (const [tool, filepath] of Object.entries(REPORT_FILES)) {
    if (tool === 'Quality Gate') continue;

    const fileStatus = getFileStatus(filepath);
    const data = loadJsonSafe(filepath);
    const findings = countFindings(tool, data);

    const entry = {
      tool,
      file: path.relative(ROOT_DIR, filepath),
      ...fileStatus,
      findings,
    };

    executionLog.scan_reports.push(entry);
    executionLog.summary.total_scans += 1;

    if (fileStatus.status === 'missing') {
      executionLog.summary.scans_missing += 1;
      console.log(`     ⚠️  ${tool}: MISSING`);
    } else {
      executionLog.summary.total_findings += findings;
      if (findings > 0) executionLog.summary.scans_with_findings += 1;
      console.log(`     ✅ ${tool}: ${findings} finding(s) (${fileStatus.size} bytes)`);
    }
  }
  console.log('');

  // Processar relatórios de validação
  console.log('  📋 Relatórios de Validação:');
  for (const [name, filepath] of Object.entries(VALIDATION_REPORTS)) {
    const fileStatus = getFileStatus(filepath);
    executionLog.validation_reports.push({
      name, file: path.relative(ROOT_DIR, filepath), ...fileStatus,
    });
    const icon = fileStatus.status === 'valid' ? '✅' : '⚠️';
    console.log(`     ${icon} ${name}: ${fileStatus.status}`);
  }
  console.log('');

  // Processar quality gate
  const gateData = loadJsonSafe(REPORT_FILES['Quality Gate']);
  if (gateData && gateData.quality_gate) {
    executionLog.quality_gate = gateData.quality_gate;
    executionLog.summary.gate_decision = gateData.quality_gate.decision;
    const icon = gateData.quality_gate.decision === 'APPROVED' ? '✅' : '❌';
    console.log(`  🏁 Quality Gate: ${icon} ${gateData.quality_gate.decision}`);
    console.log(`     Motivo: ${gateData.quality_gate.reason}`);
  } else {
    console.log('  ⚠️  Quality Gate: relatório não encontrado');
  }

  const elapsed = Date.now() - startTime;
  executionLog.metadata.elapsed_ms = elapsed;

  // Salvar
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(executionLog, null, 2), 'utf-8');

  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  Total scans: ${executionLog.summary.total_scans}`);
  console.log(`  Findings: ${executionLog.summary.total_findings}`);
  console.log(`  Missing: ${executionLog.summary.scans_missing}`);
  console.log(`  Gate: ${executionLog.summary.gate_decision}`);
  console.log(`  Relatório: ${OUTPUT_FILE}`);
  console.log(`  Duração: ${elapsed}ms`);
  console.log('══════════════════════════════════════════════════════════════');
}

module.exports = { getFileStatus, loadJsonSafe, countFindings };

if (require.main === module) { main(); }
