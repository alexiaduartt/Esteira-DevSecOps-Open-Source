/**
 * validate-findings.js
 * PBI-28 / Task 141 — Validar findings e ajustar parser se necessário
 *
 * Lê os relatórios do Semgrep e GitLeaks, extrai findings, valida campos
 * essenciais para o DefectDojo e gera um relatório de validação consolidado.
 *
 * Uso:
 *   node scripts/validate-findings.js
 *
 * Saída:
 *   reports/defectdojo/findings-validation.json
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------

const REPORTS_DIR     = path.resolve(__dirname, '..', 'reports');
const SEMGREP_REPORT  = path.join(REPORTS_DIR, 'semgrep', 'semgrep-results.json');
const GITLEAKS_REPORT = path.join(REPORTS_DIR, 'gitleaks', 'gitleaks-results.json');
const OUTPUT_DIR      = path.join(REPORTS_DIR, 'defectdojo');
const OUTPUT_FILE     = path.join(OUTPUT_DIR, 'findings-validation.json');

// Campos que o DefectDojo espera para cada scan type
const SEMGREP_REQUIRED_FIELDS  = ['check_id', 'path', 'start', 'end', 'extra'];
const GITLEAKS_REQUIRED_FIELDS = ['RuleID', 'File', 'StartLine'];

// Mapeamento de severidade do Semgrep → DefectDojo
const SEVERITY_MAP = {
  ERROR:   'High',
  WARNING: 'Medium',
  INFO:    'Low',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Carrega e parseia um arquivo JSON de forma segura.
 * @param {string} filepath
 * @returns {{ data: any, error: string|null }}
 */
function loadJson(filepath) {
  if (!fs.existsSync(filepath)) {
    return { data: null, error: `Arquivo não encontrado: ${filepath}` };
  }

  try {
    const raw = fs.readFileSync(filepath, 'utf-8');
    const data = JSON.parse(raw);
    return { data, error: null };
  } catch (err) {
    return { data: null, error: `Erro ao parsear JSON: ${err.message}` };
  }
}

/**
 * Valida campos obrigatórios em um objeto.
 * @param {object} obj
 * @param {string[]} requiredFields
 * @returns {{ valid: boolean, missing: string[] }}
 */
function validateFields(obj, requiredFields) {
  const missing = requiredFields.filter((field) => !(field in obj));
  return { valid: missing.length === 0, missing };
}

// ---------------------------------------------------------------------------
// Validação de Findings — Semgrep
// ---------------------------------------------------------------------------

/**
 * Extrai e valida findings do relatório Semgrep.
 */
function validateSemgrepFindings(data) {
  const validation = {
    tool: 'semgrep',
    scan_type: 'Semgrep JSON Report',
    status: 'valid',
    issues: [],
    summary: {
      total_findings: 0,
      by_severity: {},
      by_rule: {},
      fields_valid: true,
    },
    findings: [],
  };

  if (data === null) {
    validation.status = 'skipped';
    validation.issues.push('Relatório Semgrep não disponível');
    return validation;
  }

  // Verificar campo "results"
  if (!data.results || !Array.isArray(data.results)) {
    validation.status = 'invalid';
    validation.issues.push('Campo "results" ausente ou não é um array');
    return validation;
  }

  const results = data.results;
  validation.summary.total_findings = results.length;

  if (results.length === 0) {
    validation.issues.push('Nenhum finding encontrado — relatório limpo');
    return validation;
  }

  // Validar cada finding
  for (let i = 0; i < results.length; i++) {
    const finding = results[i];
    const { valid, missing } = validateFields(finding, SEMGREP_REQUIRED_FIELDS);

    if (!valid) {
      validation.summary.fields_valid = false;
      validation.issues.push(`Finding #${i}: campos faltando: ${missing.join(', ')}`);
    }

    // Extrair dados para resumo
    const severity = finding.extra?.severity || 'UNKNOWN';
    const ruleId   = finding.check_id || 'unknown';
    const filePath = finding.path || 'unknown';
    const line     = finding.start?.line || 0;

    // Contar por severidade
    const ddSeverity = SEVERITY_MAP[severity] || 'Info';
    validation.summary.by_severity[ddSeverity] =
      (validation.summary.by_severity[ddSeverity] || 0) + 1;

    // Contar por regra
    validation.summary.by_rule[ruleId] =
      (validation.summary.by_rule[ruleId] || 0) + 1;

    // Adicionar finding parseado
    validation.findings.push({
      index: i,
      rule_id: ruleId,
      severity: ddSeverity,
      original_severity: severity,
      file: filePath,
      line,
      message: finding.extra?.message || '',
    });
  }

  return validation;
}

// ---------------------------------------------------------------------------
// Validação de Findings — GitLeaks
// ---------------------------------------------------------------------------

/**
 * Extrai e valida findings do relatório GitLeaks.
 */
function validateGitleaksFindings(data) {
  const validation = {
    tool: 'gitleaks',
    scan_type: 'Gitleaks Scan',
    status: 'valid',
    issues: [],
    summary: {
      total_findings: 0,
      by_rule: {},
      by_file: {},
      fields_valid: true,
    },
    findings: [],
  };

  if (data === null) {
    validation.status = 'skipped';
    validation.issues.push('Relatório GitLeaks não disponível');
    return validation;
  }

  // GitLeaks gera um array JSON
  if (!Array.isArray(data)) {
    validation.status = 'invalid';
    validation.issues.push('Relatório GitLeaks não é um array JSON');
    return validation;
  }

  validation.summary.total_findings = data.length;

  if (data.length === 0) {
    validation.issues.push('Nenhum finding encontrado — nenhum secret vazado');
    return validation;
  }

  // Validar cada finding
  for (let i = 0; i < data.length; i++) {
    const finding = data[i];
    const { valid, missing } = validateFields(finding, GITLEAKS_REQUIRED_FIELDS);

    if (!valid) {
      validation.summary.fields_valid = false;
      validation.issues.push(`Finding #${i}: campos faltando: ${missing.join(', ')}`);
    }

    // Extrair dados para resumo
    const ruleId   = finding.RuleID || 'unknown';
    const filePath = finding.File || 'unknown';
    const line     = finding.StartLine || 0;

    // Contar por regra
    validation.summary.by_rule[ruleId] =
      (validation.summary.by_rule[ruleId] || 0) + 1;

    // Contar por arquivo
    validation.summary.by_file[filePath] =
      (validation.summary.by_file[filePath] || 0) + 1;

    // Adicionar finding parseado (sem expor o secret)
    validation.findings.push({
      index: i,
      rule_id: ruleId,
      file: filePath,
      line,
      commit: finding.Commit || 'N/A',
      author: finding.Author || 'N/A',
      description: finding.Description || '',
    });
  }

  return validation;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  console.log('══════════════════════════════════════════════════════════════');
  console.log('  PBI-28 │ Validação de Findings (Semgrep + GitLeaks)');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('');

  // Carregar relatórios
  const semgrepResult  = loadJson(SEMGREP_REPORT);
  const gitleaksResult = loadJson(GITLEAKS_REPORT);

  if (semgrepResult.error) {
    console.log(`  ⚠️  Semgrep: ${semgrepResult.error}`);
  } else {
    console.log('  ✅ Semgrep: relatório carregado');
  }

  if (gitleaksResult.error) {
    console.log(`  ⚠️  GitLeaks: ${gitleaksResult.error}`);
  } else {
    console.log('  ✅ GitLeaks: relatório carregado');
  }

  console.log('');

  // Validar findings
  const semgrepValidation  = validateSemgrepFindings(semgrepResult.data);
  const gitleaksValidation = validateGitleaksFindings(gitleaksResult.data);

  // Imprimir resumo Semgrep
  console.log('── Semgrep ──');
  console.log(`  Status: ${semgrepValidation.status}`);
  console.log(`  Findings: ${semgrepValidation.summary.total_findings}`);
  if (Object.keys(semgrepValidation.summary.by_severity || {}).length > 0) {
    console.log('  Por severidade:');
    for (const [sev, count] of Object.entries(semgrepValidation.summary.by_severity)) {
      console.log(`    ${sev}: ${count}`);
    }
  }
  if (semgrepValidation.issues.length > 0) {
    console.log('  Issues:');
    for (const issue of semgrepValidation.issues) {
      console.log(`    - ${issue}`);
    }
  }
  console.log('');

  // Imprimir resumo GitLeaks
  console.log('── GitLeaks ──');
  console.log(`  Status: ${gitleaksValidation.status}`);
  console.log(`  Findings: ${gitleaksValidation.summary.total_findings}`);
  if (Object.keys(gitleaksValidation.summary.by_rule || {}).length > 0) {
    console.log('  Por regra:');
    for (const [rule, count] of Object.entries(gitleaksValidation.summary.by_rule)) {
      console.log(`    ${rule}: ${count}`);
    }
  }
  if (gitleaksValidation.issues.length > 0) {
    console.log('  Issues:');
    for (const issue of gitleaksValidation.issues) {
      console.log(`    - ${issue}`);
    }
  }
  console.log('');

  // Gerar relatório de validação
  const validationReport = {
    metadata: {
      generated_at: new Date().toISOString(),
      pbi: 'PBI-28',
      task: 'Task 141',
      description: 'Validação de findings Semgrep e GitLeaks para importação no DefectDojo',
    },
    tools: [semgrepValidation, gitleaksValidation],
    overall: {
      all_valid: semgrepValidation.status !== 'invalid' && gitleaksValidation.status !== 'invalid',
      total_findings:
        semgrepValidation.summary.total_findings +
        gitleaksValidation.summary.total_findings,
    },
  };

  // Salvar relatório
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(validationReport, null, 2), 'utf-8');

  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  Relatório de validação salvo em: ${OUTPUT_FILE}`);
  console.log(`  Total de findings: ${validationReport.overall.total_findings}`);
  console.log(`  Validação geral: ${validationReport.overall.all_valid ? '✅ OK' : '❌ FALHOU'}`);
  console.log('══════════════════════════════════════════════════════════════');

  if (!validationReport.overall.all_valid) {
    process.exit(1);
  }
}

// Exports para uso como módulo
module.exports = {
  validateSemgrepFindings,
  validateGitleaksFindings,
  loadJson,
  validateFields,
  SEVERITY_MAP,
};

// Executa apenas se chamado diretamente
if (require.main === module) {
  main();
}
