/**
 * quality-gate.js
 * PBI-59 / Task 329 — Testar Comportamento de Bloco do Quality Gate
 *
 * Consolida os resultados de SAST (Semgrep), SCA (Trivy) e
 * Secret Scanning (Gitleaks), aplica a política de severidade
 * e decide se a pipeline deve ser bloqueada.
 *
 * Uso: node scripts/quality-gate.js
 * Saída: reports/quality-gate/quality-gate-report.json
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const ROOT_DIR    = path.resolve(__dirname, '..');
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');
const OUTPUT_DIR  = path.join(REPORTS_DIR, 'quality-gate');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'quality-gate-report.json');

const REPORT_PATHS = {
  semgrep:    path.join(REPORTS_DIR, 'semgrep', 'semgrep-results.json'),
  gitleaks:   path.join(REPORTS_DIR, 'gitleaks', 'gitleaks-results.json'),
  trivyFs:    path.join(REPORTS_DIR, 'trivy', 'trivy-fs-results.json'),
  trivyImage: path.join(REPORTS_DIR, 'trivy', 'trivy-image-results.json'),
};

const BLOCKING_SEVERITIES = ['HIGH', 'CRITICAL'];

const SEMGREP_SEVERITY_MAP = {
  ERROR:   'HIGH',
  WARNING: 'MEDIUM',
  INFO:    'LOW',
};

function loadJson(filepath) {
  if (!fs.existsSync(filepath)) {
    return { data: null, status: 'missing' };
  }
  try {
    const raw = fs.readFileSync(filepath, 'utf-8');
    if (raw.trim().length === 0) return { data: null, status: 'empty' };
    return { data: JSON.parse(raw), status: 'loaded' };
  } catch (err) {
    return { data: null, status: 'invalid', error: err.message };
  }
}

function normalizeSeverity(severity) {
  return String(severity || 'UNKNOWN').trim().toUpperCase();
}

function analyzeSemgrep(data) {
  const result = {
    tool: 'Semgrep (SAST)', status: 'analyzed',
    total_findings: 0, by_severity: {}, blocking_findings: [], issues: [],
  };
  if (!data || !Array.isArray(data.results)) {
    result.status = 'skipped';
    result.issues.push('Relatório Semgrep não disponível ou formato inválido.');
    return result;
  }
  result.total_findings = data.results.length;
  for (const f of data.results) {
    const orig = f.extra?.severity || 'UNKNOWN';
    const sev = SEMGREP_SEVERITY_MAP[orig] || normalizeSeverity(orig);
    result.by_severity[sev] = (result.by_severity[sev] || 0) + 1;
    if (BLOCKING_SEVERITIES.includes(sev)) {
      result.blocking_findings.push({
        rule: f.check_id || 'unknown', severity: sev,
        file: f.path || 'unknown', line: f.start?.line || 0,
        message: f.extra?.message || '',
      });
    }
  }
  return result;
}

function analyzeGitleaks(data) {
  const result = {
    tool: 'Gitleaks (Secrets)', status: 'analyzed',
    total_findings: 0, by_severity: {}, blocking_findings: [], issues: [],
  };
  if (data === null) {
    result.status = 'skipped';
    result.issues.push('Relatório Gitleaks não disponível.');
    return result;
  }
  if (!Array.isArray(data)) {
    result.status = 'skipped';
    result.issues.push('Formato do relatório Gitleaks inválido.');
    return result;
  }
  result.total_findings = data.length;
  for (const f of data) {
    const sev = 'CRITICAL';
    result.by_severity[sev] = (result.by_severity[sev] || 0) + 1;
    result.blocking_findings.push({
      rule: f.RuleID || 'unknown', severity: sev,
      file: f.File || 'unknown', line: f.StartLine || 0,
      message: f.Description || 'Secret detectado',
    });
  }
  return result;
}

function analyzeTrivy(data, label) {
  const result = {
    tool: `Trivy ${label} (SCA)`, status: 'analyzed',
    total_findings: 0, by_severity: {}, blocking_findings: [], issues: [],
  };
  if (!data || !Array.isArray(data.Results)) {
    result.status = 'skipped';
    result.issues.push(`Relatório Trivy ${label} não disponível.`);
    return result;
  }
  for (const sr of data.Results) {
    const vulns = Array.isArray(sr.Vulnerabilities) ? sr.Vulnerabilities : [];
    for (const v of vulns) {
      result.total_findings += 1;
      const sev = normalizeSeverity(v.Severity);
      result.by_severity[sev] = (result.by_severity[sev] || 0) + 1;
      if (BLOCKING_SEVERITIES.includes(sev)) {
        result.blocking_findings.push({
          rule: v.VulnerabilityID || 'unknown', severity: sev,
          package: v.PkgName || 'unknown',
          installed_version: v.InstalledVersion || 'unknown',
          fixed_version: v.FixedVersion || 'N/A',
          message: v.Title || '',
        });
      }
    }
  }
  return result;
}

function evaluateQualityGate(toolResults) {
  const gate = {
    decision: 'APPROVED', reason: '',
    total_findings: 0, total_blocking: 0,
    blocking_summary: {}, tools_analyzed: 0, tools_skipped: 0,
  };
  for (const r of toolResults) {
    if (r.status === 'skipped') { gate.tools_skipped += 1; continue; }
    gate.tools_analyzed += 1;
    gate.total_findings += r.total_findings;
    gate.total_blocking += r.blocking_findings.length;
    if (r.blocking_findings.length > 0) {
      gate.blocking_summary[r.tool] = r.blocking_findings.length;
    }
  }
  if (gate.total_blocking > 0) {
    gate.decision = 'BLOCKED';
    const tools = Object.keys(gate.blocking_summary).join(', ');
    gate.reason = `${gate.total_blocking} finding(s) bloqueante(s) em: ${tools}.`;
  } else {
    gate.reason = 'Nenhum finding com severidade bloqueante detectado.';
  }
  return gate;
}

function main() {
  const startTime = Date.now();
  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('  PBI-59 │ Quality Gate — Validação Integrada');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('');

  const loads = {
    semgrep:    loadJson(REPORT_PATHS.semgrep),
    gitleaks:   loadJson(REPORT_PATHS.gitleaks),
    trivyFs:    loadJson(REPORT_PATHS.trivyFs),
    trivyImage: loadJson(REPORT_PATHS.trivyImage),
  };

  console.log('  📥 Carregamento dos relatórios:');
  for (const [name, l] of Object.entries(loads)) {
    const icon = l.status === 'loaded' ? '✅' : '⚠️';
    console.log(`     ${icon} ${name}: ${l.status}`);
  }
  console.log('');

  const toolResults = [
    analyzeSemgrep(loads.semgrep.data),
    analyzeGitleaks(loads.gitleaks.data),
    analyzeTrivy(loads.trivyFs.data, 'FS'),
    analyzeTrivy(loads.trivyImage.data, 'Image'),
  ];

  console.log('  🔍 Análise por ferramenta:');
  for (const r of toolResults) {
    if (r.status === 'skipped') {
      console.log(`  ⏭️  ${r.tool}: SKIPPED`);
      continue;
    }
    console.log(`  📊 ${r.tool}: ${r.total_findings} finding(s)`);
    for (const [sev, count] of Object.entries(r.by_severity)) {
      const flag = BLOCKING_SEVERITIES.includes(sev) ? ' 🚫' : '';
      console.log(`       ${sev}: ${count}${flag}`);
    }
    if (r.blocking_findings.length > 0) {
      console.log(`     ❌ Bloqueantes: ${r.blocking_findings.length}`);
    } else {
      console.log('     ✅ Nenhum bloqueante');
    }
  }
  console.log('');

  const gate = evaluateQualityGate(toolResults);
  const elapsed = Date.now() - startTime;

  const report = {
    metadata: {
      pbi: 'PBI-59', task: 'Task 329',
      description: 'Validação Integrada do Quality Gate',
      generated_at: new Date().toISOString(),
      elapsed_ms: elapsed,
      blocking_severities: BLOCKING_SEVERITIES,
    },
    tools: toolResults,
    quality_gate: gate,
  };

  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(report, null, 2), 'utf-8');

  console.log('══════════════════════════════════════════════════════════════');
  if (gate.decision === 'BLOCKED') {
    console.log('  ❌ QUALITY GATE: BLOQUEADO');
    console.log('══════════════════════════════════════════════════════════════');
    console.log(`  ${gate.reason}`);
    for (const [tool, count] of Object.entries(gate.blocking_summary)) {
      console.log(`    • ${tool}: ${count}`);
    }
  } else {
    console.log('  ✅ QUALITY GATE: APROVADO');
    console.log('══════════════════════════════════════════════════════════════');
    console.log(`  ${gate.reason}`);
  }
  console.log(`  Total: ${gate.total_findings} | Bloqueantes: ${gate.total_blocking}`);
  console.log(`  Ferramentas: ${gate.tools_analyzed} analisadas | ${gate.tools_skipped} ignoradas`);
  console.log(`  Relatório: ${OUTPUT_FILE}`);
  console.log(`  Duração: ${elapsed}ms`);
  console.log('══════════════════════════════════════════════════════════════');

  process.exit(gate.decision === 'BLOCKED' ? 1 : 0);
}

module.exports = {
  analyzeSemgrep, analyzeGitleaks, analyzeTrivy,
  evaluateQualityGate, loadJson, BLOCKING_SEVERITIES,
};

if (require.main === module) { main(); }
