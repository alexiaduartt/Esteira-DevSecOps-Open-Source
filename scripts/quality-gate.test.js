/**
 * quality-gate.test.js
 * PBI-59 / Task 329 — Testes do Quality Gate integrado
 *
 * Valida os cenários de aprovação e bloqueio do quality gate.
 */

'use strict';

const {
  analyzeSemgrep,
  analyzeGitleaks,
  analyzeTrivy,
  evaluateQualityGate,
} = require('./quality-gate');

// ── Semgrep (SAST) ──

describe('PBI-59 — Quality Gate: Semgrep (SAST)', () => {

  test('deve retornar skipped quando dados são nulos', () => {
    const result = analyzeSemgrep(null);
    expect(result.status).toBe('skipped');
    expect(result.total_findings).toBe(0);
  });

  test('deve retornar 0 findings quando results está vazio', () => {
    const result = analyzeSemgrep({ results: [] });
    expect(result.status).toBe('analyzed');
    expect(result.total_findings).toBe(0);
    expect(result.blocking_findings).toHaveLength(0);
  });

  test('deve detectar finding bloqueante (ERROR → HIGH)', () => {
    const data = {
      results: [{
        check_id: 'test.rule',
        path: 'app.js',
        start: { line: 10 },
        end: { line: 10 },
        extra: { severity: 'ERROR', message: 'XSS detectado' },
      }],
    };
    const result = analyzeSemgrep(data);
    expect(result.total_findings).toBe(1);
    expect(result.blocking_findings).toHaveLength(1);
    expect(result.blocking_findings[0].severity).toBe('HIGH');
  });

  test('não deve bloquear para WARNING (MEDIUM)', () => {
    const data = {
      results: [{
        check_id: 'test.warning',
        path: 'app.js',
        start: { line: 5 },
        end: { line: 5 },
        extra: { severity: 'WARNING', message: 'Alerta' },
      }],
    };
    const result = analyzeSemgrep(data);
    expect(result.total_findings).toBe(1);
    expect(result.blocking_findings).toHaveLength(0);
    expect(result.by_severity['MEDIUM']).toBe(1);
  });

});

// ── Gitleaks (Secrets) ──

describe('PBI-59 — Quality Gate: Gitleaks (Secrets)', () => {

  test('deve retornar skipped quando dados são nulos', () => {
    const result = analyzeGitleaks(null);
    expect(result.status).toBe('skipped');
  });

  test('deve retornar 0 findings para array vazio', () => {
    const result = analyzeGitleaks([]);
    expect(result.status).toBe('analyzed');
    expect(result.total_findings).toBe(0);
    expect(result.blocking_findings).toHaveLength(0);
  });

  test('deve classificar secrets como CRITICAL (bloqueante)', () => {
    const data = [{
      RuleID: 'generic-api-key',
      File: 'config.js',
      StartLine: 12,
      Description: 'API key detectada',
    }];
    const result = analyzeGitleaks(data);
    expect(result.total_findings).toBe(1);
    expect(result.blocking_findings).toHaveLength(1);
    expect(result.blocking_findings[0].severity).toBe('CRITICAL');
  });

});

// ── Trivy (SCA) ──

describe('PBI-59 — Quality Gate: Trivy (SCA)', () => {

  test('deve retornar skipped quando dados são nulos', () => {
    const result = analyzeTrivy(null, 'FS');
    expect(result.status).toBe('skipped');
  });

  test('deve retornar 0 findings para Results sem vulnerabilidades', () => {
    const data = { Results: [{ Vulnerabilities: null }] };
    const result = analyzeTrivy(data, 'FS');
    expect(result.total_findings).toBe(0);
    expect(result.blocking_findings).toHaveLength(0);
  });

  test('deve bloquear para vulnerabilidade HIGH', () => {
    const data = {
      Results: [{
        Vulnerabilities: [{
          VulnerabilityID: 'CVE-2024-99999',
          PkgName: 'test-pkg',
          InstalledVersion: '1.0.0',
          Severity: 'HIGH',
          Title: 'Vulnerabilidade simulada',
        }],
      }],
    };
    const result = analyzeTrivy(data, 'FS');
    expect(result.total_findings).toBe(1);
    expect(result.blocking_findings).toHaveLength(1);
  });

  test('não deve bloquear para vulnerabilidade MEDIUM', () => {
    const data = {
      Results: [{
        Vulnerabilities: [{
          VulnerabilityID: 'CVE-2024-11111',
          PkgName: 'ok-pkg',
          InstalledVersion: '2.0.0',
          Severity: 'MEDIUM',
        }],
      }],
    };
    const result = analyzeTrivy(data, 'Image');
    expect(result.total_findings).toBe(1);
    expect(result.blocking_findings).toHaveLength(0);
  });

});

// ── Quality Gate (Decisão) ──

describe('PBI-59 — Quality Gate: Decisão Final', () => {

  test('deve aprovar quando não há findings bloqueantes', () => {
    const results = [
      { status: 'analyzed', total_findings: 2, blocking_findings: [], tool: 'A' },
      { status: 'analyzed', total_findings: 1, blocking_findings: [], tool: 'B' },
    ];
    const gate = evaluateQualityGate(results);
    expect(gate.decision).toBe('APPROVED');
    expect(gate.total_blocking).toBe(0);
    expect(gate.tools_analyzed).toBe(2);
  });

  test('deve bloquear quando há findings bloqueantes', () => {
    const results = [
      { status: 'analyzed', total_findings: 1, blocking_findings: [{ rule: 'x' }], tool: 'A' },
      { status: 'analyzed', total_findings: 0, blocking_findings: [], tool: 'B' },
    ];
    const gate = evaluateQualityGate(results);
    expect(gate.decision).toBe('BLOCKED');
    expect(gate.total_blocking).toBe(1);
  });

  test('deve contar ferramentas skipped corretamente', () => {
    const results = [
      { status: 'skipped', total_findings: 0, blocking_findings: [], tool: 'A' },
      { status: 'analyzed', total_findings: 0, blocking_findings: [], tool: 'B' },
    ];
    const gate = evaluateQualityGate(results);
    expect(gate.decision).toBe('APPROVED');
    expect(gate.tools_skipped).toBe(1);
    expect(gate.tools_analyzed).toBe(1);
  });

});
