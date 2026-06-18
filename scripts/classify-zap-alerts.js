/**
 * classify-zap-alerts.js
 * PBI-25 — Governança DAST
 *
 * Tasks cobertas:
 *   Task 123 — Classificar alertas DAST (por severidade via riskcode)
 *   Task 124 — Separar alertas por nível (agrupar + resumo stdout)
 *   Task 126 — Formatar relatório para o DefectDojo (ZAP Scan JSON)
 *   Task 127 — Mapear riscos com OWASP Top 10 (via cweid)
 *
 * Uso:
 *   node scripts/classify-zap-alerts.js [caminho/para/zap-report.json]
 *
 * Se nenhum caminho for informado, procura o JSON mais recente em reports/zap/.
 * Se o arquivo não existir (ZAP não rodou), loga um aviso e encerra com exit(0).
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

const RISK_LEVELS = {
  0: 'informational',
  1: 'low',
  2: 'medium',
  3: 'high',
};

const REPORTS_DIR  = path.resolve(__dirname, '..', 'reports', 'zap');
const MAPPING_FILE = path.resolve(__dirname, '..', 'security', 'owasp-top10-mapping.json');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Formata a data atual no padrão DDMMAAAA usado na nomenclatura de relatórios.
 */
function getDateStamp() {
  const now = new Date();
  const dd   = String(now.getDate()).padStart(2, '0');
  const mm   = String(now.getMonth() + 1).padStart(2, '0');
  const yyyy = now.getFullYear();
  return `${dd}${mm}${yyyy}`;
}

/**
 * Carrega o mapeamento CWE → OWASP Top 10:2025 de security/owasp-top10-mapping.json.
 * Retorna { cwe_mapping, categories } ou null se o arquivo não existir.
 */
function loadOwaspMapping() {
  if (!fs.existsSync(MAPPING_FILE)) {
    console.warn(`[AVISO] Arquivo de mapeamento OWASP Top 10 não encontrado: ${MAPPING_FILE}`);
    return null;
  }
  try {
    const raw = fs.readFileSync(MAPPING_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    console.warn(`[AVISO] Erro ao ler mapeamento OWASP Top 10: ${err.message}`);
    return null;
  }
}

/**
 * Localiza o arquivo JSON de saída do ZAP mais recente em reports/zap/.
 * Ignora arquivos gerados por este próprio script (que contêm "pbi25" no nome).
 */
function findLatestZapReport() {
  if (!fs.existsSync(REPORTS_DIR)) {
    return null;
  }

  // Prioriza o arquivo de relatório oficial gerado no pipeline pelo OWASP ZAP
  const officialReport = path.join(REPORTS_DIR, 'report_json.json');
  if (fs.existsSync(officialReport)) {
    return officialReport;
  }

  // Busca outro arquivo JSON como fallback, ignorando arquivos de mock e de governança
  const files = fs.readdirSync(REPORTS_DIR)
    .filter((f) => f.endsWith('.json') && !f.includes('pbi25') && !f.includes('mock'))
    .map((f) => ({
      name: f,
      mtime: fs.statSync(path.join(REPORTS_DIR, f)).mtimeMs,
    }))
    .sort((a, b) => b.mtime - a.mtime);

  return files.length > 0 ? path.join(REPORTS_DIR, files[0].name) : null;
}

// ---------------------------------------------------------------------------
// Task 123 — Classificar alertas DAST
// ---------------------------------------------------------------------------

/**
 * Extrai todos os alertas do JSON de saída do ZAP e classifica cada um
 * pela severidade (informational | low | medium | high) usando o campo riskcode.
 *
 * @param {object} zapJson - JSON de saída do OWASP ZAP
 * @returns {Array<object>} Lista de alertas classificados
 */
function classifyAlerts(zapJson) {
  const alerts = [];

  // O ZAP organiza os alertas dentro de site[].alerts[]
  const sites = zapJson.site || [];

  for (const site of sites) {
    const siteAlerts = site.alerts || [];

    for (const alert of siteAlerts) {
      const riskcode = parseInt(alert.riskcode, 10);
      const severity = RISK_LEVELS[riskcode] || 'informational';

      alerts.push({
        ...alert,
        _severity: severity,
        _riskcode: riskcode,
      });
    }
  }

  return alerts;
}

// ---------------------------------------------------------------------------
// Task 124 — Separar alertas por nível
// ---------------------------------------------------------------------------

/**
 * Agrupa os alertas classificados em um objeto com chaves por severidade.
 *
 * @param {Array<object>} classifiedAlerts
 * @returns {{ informational: Array, low: Array, medium: Array, high: Array }}
 */
function groupByLevel(classifiedAlerts) {
  const grouped = {
    informational: [],
    low: [],
    medium: [],
    high: [],
  };

  for (const alert of classifiedAlerts) {
    const level = alert._severity;
    if (grouped[level]) {
      grouped[level].push(alert);
    } else {
      grouped.informational.push(alert);
    }
  }

  return grouped;
}

/**
 * Imprime no stdout o resumo com a contagem de alertas por nível.
 */
function printSummary(grouped) {
  console.log('\n══════════════════════════════════════════════');
  console.log('  PBI-25 │ Resumo de Alertas DAST (OWASP ZAP)');
  console.log('══════════════════════════════════════════════');
  console.log(`  🔵 Informational : ${grouped.informational.length}`);
  console.log(`  🟡 Low           : ${grouped.low.length}`);
  console.log(`  🟠 Medium        : ${grouped.medium.length}`);
  console.log(`  🔴 High          : ${grouped.high.length}`);
  console.log('──────────────────────────────────────────────');
  const total = grouped.informational.length + grouped.low.length
              + grouped.medium.length + grouped.high.length;
  console.log(`  Total            : ${total}`);
  console.log('══════════════════════════════════════════════\n');
}

// ---------------------------------------------------------------------------
// Task 127 — Mapear riscos com OWASP Top 10
// ---------------------------------------------------------------------------

/**
 * Enriquece os alertas classificados com a categoria OWASP Top 10:2025 correspondente,
 * utilizando o campo cweid do alerta e o mapeamento em security/owasp-top10-mapping.json.
 *
 * Se um cweid não possuir mapeamento, os campos _owaspCategory e _owaspLabel
 * serão definidos como null (sem lançar erro).
 *
 * @param {Array<object>} classifiedAlerts
 * @param {object|null}   mapping - mapeamento carregado por loadOwaspMapping()
 * @returns {Array<object>} Alertas com campos _owaspCategory e _owaspLabel adicionados
 */
function mapOwaspTop10(classifiedAlerts, mapping) {
  if (!mapping) {
    // Sem mapeamento disponível — define campos como null
    return classifiedAlerts.map((a) => ({
      ...a,
      _owaspCategory: null,
      _owaspLabel: null,
    }));
  }

  const cweMap     = mapping.cwe_mapping || {};
  const categories = mapping.categories || {};

  return classifiedAlerts.map((alert) => {
    const cwe      = String(alert.cweid || '');
    const category = cweMap[cwe] || null;
    const label    = category ? (categories[category] || null) : null;

    return {
      ...alert,
      _owaspCategory: category,
      _owaspLabel: label ? `${category} - ${label}` : null,
    };
  });
}

/**
 * Imprime no stdout o resumo de mapeamento OWASP Top 10.
 */
function printOwaspSummary(enrichedAlerts) {
  const counts = {};
  for (const alert of enrichedAlerts) {
    const label = alert._owaspLabel || '(CWE não mapeado)';
    counts[label] = (counts[label] || 0) + 1;
  }

  console.log('══════════════════════════════════════════════');
  console.log('  PBI-25 │ Mapeamento OWASP Top 10:2025');
  console.log('══════════════════════════════════════════════');

  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  for (const [label, count] of sorted) {
    console.log(`  ${label}: ${count} alerta(s)`);
  }

  console.log('══════════════════════════════════════════════\n');
}

// ---------------------------------------------------------------------------
// Task 126 — Formatar relatório para o DefectDojo
// ---------------------------------------------------------------------------

/**
 * Transforma os alertas enriquecidos no formato ZAP Scan JSON compatível com
 * a importação do DefectDojo, e salva em reports/zap/ seguindo a nomenclatura:
 *   zap-[DDMMAAAA]-[pbi25].json
 *
 * @param {object}       zapJson         - JSON original do ZAP (preserva metadados)
 * @param {Array<object>} enrichedAlerts  - Alertas com severidade e OWASP Top 10
 * @returns {string} Caminho do arquivo salvo
 */
function formatForDefectDojo(zapJson, enrichedAlerts) {
  // Reconstruir no formato ZAP Scan JSON esperado pelo DefectDojo,
  // adicionando os campos de enriquecimento como tags extras.
  const sites = zapJson.site || [];

  const formattedSites = sites.map((site) => {
    const formattedAlerts = (site.alerts || []).map((originalAlert) => {
      // Encontra o alerta enriquecido correspondente
      const enriched = enrichedAlerts.find(
        (e) => e.alertRef === originalAlert.alertRef
            && e.pluginid === originalAlert.pluginid
      ) || {};

      return {
        ...originalAlert,
        // Campos adicionais para governança — o DefectDojo aceita campos extras
        _governance: {
          severity: enriched._severity || RISK_LEVELS[parseInt(originalAlert.riskcode, 10)] || 'informational',
          owaspCategory: enriched._owaspCategory || null,
          owaspLabel: enriched._owaspLabel || null,
          pbi: 'PBI-25',
          classifiedAt: new Date().toISOString(),
        },
      };
    });

    return {
      ...site,
      alerts: formattedAlerts,
    };
  });

  const defectDojoReport = {
    '@version': zapJson['@version'] || '2.16.0',
    '@generated': zapJson['@generated'] || new Date().toISOString(),
    _pbi: 'PBI-25',
    _generatedBy: 'classify-zap-alerts.js',
    site: formattedSites,
  };

  // Salvar usando a nomenclatura padrão: zap-DDMMAAAA-pbi25.json
  const filename = `zap-${getDateStamp()}-pbi25.json`;
  const outputPath = path.join(REPORTS_DIR, filename);

  // Garante que o diretório existe
  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }

  fs.writeFileSync(outputPath, JSON.stringify(defectDojoReport, null, 2), 'utf-8');

  return outputPath;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  // Determinar o caminho do relatório ZAP
  const inputArg   = process.argv[2];
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

  console.log(`[INFO] Lendo relatório ZAP: ${zapReportPath}`);

  let zapJson;
  try {
    const raw = fs.readFileSync(zapReportPath, 'utf-8');
    zapJson = JSON.parse(raw);
  } catch (err) {
    console.error(`[ERRO] Falha ao ler/parsear o relatório ZAP: ${err.message}`);
    process.exit(1);
  }

  // Task 123 — Classificar alertas
  const classifiedAlerts = classifyAlerts(zapJson);
  console.log(`[INFO] ${classifiedAlerts.length} alerta(s) classificado(s).`);

  // Task 124 — Agrupar por nível e imprimir resumo
  const grouped = groupByLevel(classifiedAlerts);
  printSummary(grouped);

  // Task 127 — Mapear OWASP Top 10
  const owaspMapping   = loadOwaspMapping();
  const enrichedAlerts = mapOwaspTop10(classifiedAlerts, owaspMapping);
  printOwaspSummary(enrichedAlerts);

  // Task 126 — Formatar e salvar para DefectDojo
  const outputPath = formatForDefectDojo(zapJson, enrichedAlerts);
  console.log(`[INFO] Relatório formatado para DefectDojo salvo em: ${outputPath}`);

  // Retornar dados para uso programático (quando importado como módulo)
  return { classifiedAlerts, grouped, enrichedAlerts, outputPath };
}

// ---------------------------------------------------------------------------
// Exports (para uso como módulo e para o check-zap-gate.js)
// ---------------------------------------------------------------------------

module.exports = {
  classifyAlerts,
  groupByLevel,
  mapOwaspTop10,
  formatForDefectDojo,
  printSummary,
  printOwaspSummary,
  loadOwaspMapping,
  findLatestZapReport,
  RISK_LEVELS,
};

// Executa apenas se chamado diretamente (não quando importado)
if (require.main === module) {
  main();
}
