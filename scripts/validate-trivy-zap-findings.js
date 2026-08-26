'use strict';

/**
 * Valida os findings e as severidades presentes nos relatórios do Trivy,
 * do SBOM CycloneDX e do OWASP ZAP antes da importação no DefectDojo.
 *
 * O resultado consolidado é salvo em:
 * reports/defectdojo/trivy-zap-findings-validation.json
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');
const OUTPUT_DIR = path.join(REPORTS_DIR, 'defectdojo');

const REPORT_FILES = {
  trivyFs: path.join(
    REPORTS_DIR,
    'trivy',
    'trivy-fs-results.json',
  ),
  trivyImage: path.join(
    REPORTS_DIR,
    'trivy',
    'trivy-image-results.json',
  ),
  cyclonedx: path.join(
    REPORTS_DIR,
    'trivy',
    'sbom',
    'sbom-cyclonedx.json',
  ),
  zap: path.join(
    REPORTS_DIR,
    'zap',
    'report_json.json',
  ),
};

const OUTPUT_FILE = path.join(
  OUTPUT_DIR,
  'trivy-zap-findings-validation.json',
);

const SEVERITY_ORDER = [
  'Info',
  'Low',
  'Medium',
  'High',
  'Critical',
  'Unknown',
];

function log(level, component, message) {
  console.log(`[${level}] [${component}] ${message}`);
}

function logDetail(key, value) {
  console.log(`       ${key}=${value}`);
}

function toPortablePath(filePath) {
  return filePath.split(path.sep).join('/');
}

function createSeverityCounter() {
  return {
    Info: 0,
    Low: 0,
    Medium: 0,
    High: 0,
    Critical: 0,
    Unknown: 0,
  };
}

function incrementSeverity(counter, severity) {
  const normalizedSeverity = SEVERITY_ORDER.includes(severity)
    ? severity
    : 'Unknown';

  counter[normalizedSeverity] += 1;
}

function loadJson(filePath) {
  if (!fs.existsSync(filePath)) {
    return {
      status: 'missing',
      data: null,
      error: null,
    };
  }

  try {
    const content = fs.readFileSync(filePath, 'utf8');

    if (content.trim().length === 0) {
      return {
        status: 'invalid',
        data: null,
        error: 'O arquivo está vazio.',
      };
    }

    return {
      status: 'valid',
      data: JSON.parse(content),
      error: null,
    };
  } catch (error) {
    return {
      status: 'invalid',
      data: null,
      error: `Não foi possível interpretar o JSON: ${error.message}`,
    };
  }
}

function normalizeTrivySeverity(severity) {
  const normalizedValue = String(severity || '')
    .trim()
    .toUpperCase();

  const severityMap = {
    UNKNOWN: 'Unknown',
    INFO: 'Info',
    LOW: 'Low',
    MEDIUM: 'Medium',
    HIGH: 'High',
    CRITICAL: 'Critical',
  };

  return severityMap[normalizedValue] || 'Unknown';
}

function normalizeCycloneDxSeverity(severity) {
  const normalizedValue = String(severity || '')
    .trim()
    .toLowerCase();

  const severityMap = {
    unknown: 'Unknown',
    none: 'Info',
    info: 'Info',
    informational: 'Info',
    low: 'Low',
    medium: 'Medium',
    moderate: 'Medium',
    high: 'High',
    critical: 'Critical',
  };

  return severityMap[normalizedValue] || 'Unknown';
}

function normalizeZapSeverity(alert) {
  const riskCode = String(alert.riskcode ?? '').trim();

  const riskCodeMap = {
    0: 'Info',
    1: 'Low',
    2: 'Medium',
    3: 'High',
  };

  if (riskCode in riskCodeMap) {
    return riskCodeMap[riskCode];
  }

  const riskDescription = String(alert.riskdesc || '')
    .split(' ')[0]
    .trim()
    .toLowerCase();

  const descriptionMap = {
    informational: 'Info',
    info: 'Info',
    low: 'Low',
    medium: 'Medium',
    high: 'High',
  };

  return descriptionMap[riskDescription] || 'Unknown';
}

function selectHighestSeverity(severities) {
  const ranking = {
    Unknown: 0,
    Info: 1,
    Low: 2,
    Medium: 3,
    High: 4,
    Critical: 5,
  };

  if (severities.length === 0) {
    return 'Unknown';
  }

  return severities.reduce((highest, current) => {
    return ranking[current] > ranking[highest]
      ? current
      : highest;
  }, 'Unknown');
}

function createValidationResult({
  component,
  scanType,
  filePath,
}) {
  const relativeFilePath = path.relative(
    ROOT_DIR,
    filePath,
  );

  return {
    component,
    scan_type: scanType,
    file: toPortablePath(relativeFilePath),
    status: 'valid',
    issues: [],
    summary: {
      total_findings: 0,
      severity_counts: createSeverityCounter(),
      fields_valid: true,
      severities_valid: true,
    },
  };
}

function validateRequiredFields(
  item,
  requiredFields,
  missingFields,
) {
  let valid = true;

  for (const field of requiredFields) {
    if (!(field in item)) {
      missingFields.add(field);
      valid = false;
    }
  }

  return valid;
}

function handleLoadFailure(result, loadResult) {
  if (loadResult.status === 'missing') {
    result.status = 'skipped';
    result.summary.fields_valid = null;
    result.summary.severities_valid = null;
    result.issues.push('Relatório não encontrado.');

    return true;
  }

  if (loadResult.status === 'invalid') {
    result.status = 'invalid';
    result.summary.fields_valid = false;
    result.summary.severities_valid = false;
    result.issues.push(loadResult.error);

    return true;
  }

  return false;
}

function validateTrivyReport({
  component,
  filePath,
}) {
  const result = createValidationResult({
    component,
    scanType: 'Trivy Scan',
    filePath,
  });

  const loadResult = loadJson(filePath);

  if (handleLoadFailure(result, loadResult)) {
    return result;
  }

  const data = loadResult.data;

  if (!Array.isArray(data.Results)) {
    result.status = 'invalid';
    result.summary.fields_valid = false;
    result.issues.push(
      'O campo Results está ausente ou não contém um array.',
    );

    return result;
  }

  const missingFields = new Set();
  const unknownSeverities = new Set();

  const requiredFields = [
    'VulnerabilityID',
    'PkgName',
    'InstalledVersion',
    'Severity',
  ];

  for (const scanResult of data.Results) {
    const vulnerabilities = Array.isArray(
      scanResult.Vulnerabilities,
    )
      ? scanResult.Vulnerabilities
      : [];

    for (const vulnerability of vulnerabilities) {
      result.summary.total_findings += 1;

      const fieldsValid = validateRequiredFields(
        vulnerability,
        requiredFields,
        missingFields,
      );

      if (!fieldsValid) {
        result.summary.fields_valid = false;
      }

      const severity = normalizeTrivySeverity(
        vulnerability.Severity,
      );

      incrementSeverity(
        result.summary.severity_counts,
        severity,
      );

      if (severity === 'Unknown') {
        result.summary.severities_valid = false;

        unknownSeverities.add(
          String(vulnerability.Severity || 'undefined'),
        );
      }
    }
  }

  if (missingFields.size > 0) {
    result.status = 'invalid';

    result.issues.push(
      `Campos obrigatórios ausentes: ${
        Array.from(missingFields).join(', ')
      }.`,
    );
  }

  if (unknownSeverities.size > 0) {
    result.status = 'invalid';

    result.issues.push(
      `Severidades não reconhecidas: ${
        Array.from(unknownSeverities).join(', ')
      }.`,
    );
  }

  if (result.summary.total_findings === 0) {
    result.issues.push(
      'Nenhuma vulnerabilidade foi encontrada no relatório.',
    );
  }

  return result;
}

function validateCycloneDxReport() {
  const result = createValidationResult({
    component: 'SBOM CycloneDX',
    scanType: 'CycloneDX Scan',
    filePath: REPORT_FILES.cyclonedx,
  });

  result.summary.total_components = 0;

  const loadResult = loadJson(REPORT_FILES.cyclonedx);

  if (handleLoadFailure(result, loadResult)) {
    return result;
  }

  const data = loadResult.data;

  if (data.bomFormat !== 'CycloneDX') {
    result.status = 'invalid';
    result.summary.fields_valid = false;

    result.issues.push(
      'O campo bomFormat não possui o valor CycloneDX.',
    );
  }

  if (!Array.isArray(data.components)) {
    result.status = 'invalid';
    result.summary.fields_valid = false;

    result.issues.push(
      'O campo components está ausente ou não contém um array.',
    );

    return result;
  }

  result.summary.total_components = data.components.length;

  const vulnerabilities = Array.isArray(data.vulnerabilities)
    ? data.vulnerabilities
    : [];

  const missingFields = new Set();
  const unknownSeverities = new Set();

  for (const vulnerability of vulnerabilities) {
    result.summary.total_findings += 1;

    if (!('id' in vulnerability)) {
      missingFields.add('id');
      result.summary.fields_valid = false;
    }

    const ratings = Array.isArray(vulnerability.ratings)
      ? vulnerability.ratings
      : [];

    const severities = ratings.map((rating) => {
      return normalizeCycloneDxSeverity(rating.severity);
    });

    const severity = selectHighestSeverity(severities);

    incrementSeverity(
      result.summary.severity_counts,
      severity,
    );

    if (severity === 'Unknown') {
      result.summary.severities_valid = false;

      const originalSeverities = ratings.map((rating) => {
        return String(rating.severity || 'undefined');
      });

      unknownSeverities.add(
        originalSeverities.join(',') || 'undefined',
      );
    }
  }

  if (missingFields.size > 0) {
    result.status = 'invalid';

    result.issues.push(
      `Campos obrigatórios ausentes: ${
        Array.from(missingFields).join(', ')
      }.`,
    );
  }

  if (unknownSeverities.size > 0) {
    result.status = 'invalid';

    result.issues.push(
      `Severidades não reconhecidas: ${
        Array.from(unknownSeverities).join(', ')
      }.`,
    );
  }

  if (vulnerabilities.length === 0) {
    result.issues.push(
      'O SBOM não declara vulnerabilidades. A validação de severidades não se aplica a este relatório.',
    );
  }

  return result;
}

function validateZapReport() {
  const result = createValidationResult({
    component: 'OWASP ZAP',
    scanType: 'ZAP Scan',
    filePath: REPORT_FILES.zap,
  });

  result.summary.total_sites = 0;

  const loadResult = loadJson(REPORT_FILES.zap);

  if (handleLoadFailure(result, loadResult)) {
    return result;
  }

  const data = loadResult.data;

  if (!Array.isArray(data.site)) {
    result.status = 'invalid';
    result.summary.fields_valid = false;

    result.issues.push(
      'O campo site está ausente ou não contém um array.',
    );

    return result;
  }

  result.summary.total_sites = data.site.length;

  const missingFields = new Set();
  const unknownSeverities = new Set();

  const requiredFields = [
    'alert',
    'riskcode',
    'riskdesc',
  ];

  for (const site of data.site) {
    const alerts = Array.isArray(site.alerts)
      ? site.alerts
      : [];

    for (const alert of alerts) {
      result.summary.total_findings += 1;

      const fieldsValid = validateRequiredFields(
        alert,
        requiredFields,
        missingFields,
      );

      if (!fieldsValid) {
        result.summary.fields_valid = false;
      }

      const severity = normalizeZapSeverity(alert);

      incrementSeverity(
        result.summary.severity_counts,
        severity,
      );

      if (severity === 'Unknown') {
        result.summary.severities_valid = false;

        unknownSeverities.add(
          String(
            alert.riskdesc
              || alert.riskcode
              || 'undefined',
          ),
        );
      }
    }
  }

  if (missingFields.size > 0) {
    result.status = 'invalid';

    result.issues.push(
      `Campos obrigatórios ausentes: ${
        Array.from(missingFields).join(', ')
      }.`,
    );
  }

  if (unknownSeverities.size > 0) {
    result.status = 'invalid';

    result.issues.push(
      `Severidades não reconhecidas: ${
        Array.from(unknownSeverities).join(', ')
      }.`,
    );
  }

  if (result.summary.total_findings === 0) {
    result.issues.push(
      'Nenhum alerta foi encontrado no relatório.',
    );
  }

  return result;
}

function aggregateSeverityCounts(results) {
  const aggregate = createSeverityCounter();

  for (const result of results) {
    for (const severity of SEVERITY_ORDER) {
      aggregate[severity] += (
        result.summary.severity_counts[severity] || 0
      );
    }
  }

  return aggregate;
}

function printValidationResult(result) {
  if (result.status === 'skipped') {
    log(
      'WARN',
      result.component,
      'Relatório não encontrado. A validação foi ignorada.',
    );

    logDetail('path', result.file);
    return;
  }

  if (result.status === 'invalid') {
    log(
      'ERROR',
      result.component,
      'O relatório contém findings ou severidades inválidas.',
    );
  } else {
    log(
      'OK',
      result.component,
      'Findings e severidades validados com sucesso.',
    );
  }

  logDetail(
    'total_findings',
    result.summary.total_findings,
  );

  if ('total_components' in result.summary) {
    logDetail(
      'total_components',
      result.summary.total_components,
    );
  }

  if ('total_sites' in result.summary) {
    logDetail(
      'total_sites',
      result.summary.total_sites,
    );
  }

  for (const severity of SEVERITY_ORDER) {
    const total = result.summary
      .severity_counts[severity];

    if (total > 0) {
      logDetail(`severity.${severity}`, total);
    }
  }

  for (const issue of result.issues) {
    logDetail('issue', issue);
  }
}

function buildValidationReport(results) {
  const validTools = results.filter((result) => {
    return result.status === 'valid';
  }).length;

  const skippedTools = results.filter((result) => {
    return result.status === 'skipped';
  }).length;

  const invalidTools = results.filter((result) => {
    return result.status === 'invalid';
  }).length;

  const totalFindings = results.reduce(
    (total, result) => {
      return total + result.summary.total_findings;
    },
    0,
  );

  return {
    metadata: {
      generated_at: new Date().toISOString(),
      description:
        'Validação dos findings e das severidades dos relatórios destinados ao DefectDojo.',
    },
    tools: results,
    overall: {
      status: invalidTools > 0
        ? 'failed'
        : skippedTools > 0
          ? 'completed_with_warnings'
          : 'success',
      valid_tools: validTools,
      skipped_tools: skippedTools,
      invalid_tools: invalidTools,
      total_findings: totalFindings,
      severity_counts: aggregateSeverityCounts(results),
    },
  };
}

function saveValidationReport(report) {
  fs.mkdirSync(OUTPUT_DIR, {
    recursive: true,
  });

  fs.writeFileSync(
    OUTPUT_FILE,
    `${JSON.stringify(report, null, 2)}\n`,
    'utf8',
  );
}

function main() {
  log(
    'INFO',
    'DefectDojo',
    'Iniciando validação dos findings e das severidades.',
  );

  console.log('');

  const results = [
    validateTrivyReport({
      component: 'Trivy FS',
      filePath: REPORT_FILES.trivyFs,
    }),
    validateTrivyReport({
      component: 'Trivy Image',
      filePath: REPORT_FILES.trivyImage,
    }),
    validateCycloneDxReport(),
    validateZapReport(),
  ];

  for (const result of results) {
    printValidationResult(result);
  }

  const report = buildValidationReport(results);

  saveValidationReport(report);

  const relativeOutputPath = path.relative(
    ROOT_DIR,
    OUTPUT_FILE,
  );

  console.log('');

  log(
    'SUMMARY',
    'DefectDojo',
    `status=${report.overall.status} `
      + `valid=${report.overall.valid_tools} `
      + `skipped=${report.overall.skipped_tools} `
      + `invalid=${report.overall.invalid_tools} `
      + `findings=${report.overall.total_findings}`,
  );

  logDetail(
    'output',
    toPortablePath(relativeOutputPath),
  );

  if (report.overall.invalid_tools > 0) {
    log(
      'ERROR',
      'DefectDojo',
      'A validação identificou findings ou severidades inválidas.',
    );

    process.exit(1);
  }

  if (report.overall.skipped_tools > 0) {
    log(
      'INFO',
      'DefectDojo',
      'Os relatórios ausentes podem ser gerados durante a execução da pipeline.',
    );

    process.exit(0);
  }

  log(
    'INFO',
    'DefectDojo',
    'Todos os findings e severidades foram validados.',
  );
}

module.exports = {
  aggregateSeverityCounts,
  loadJson,
  normalizeCycloneDxSeverity,
  normalizeTrivySeverity,
  normalizeZapSeverity,
  selectHighestSeverity,
  toPortablePath,
  validateCycloneDxReport,
  validateTrivyReport,
  validateZapReport,
};

if (require.main === module) {
  main();
}