# Guia de Importação de Relatórios no DefectDojo

## Objetivo

Este documento descreve o fluxo de validação e importação dos relatórios de segurança gerados pela esteira DevSecOps para o DefectDojo.

A integração centraliza os findings em um único ambiente, facilitando a análise das vulnerabilidades, a identificação da ferramenta de origem, o acompanhamento das severidades e o gerenciamento do status de tratamento.

## Escopo

O fluxo contempla os seguintes relatórios:

- Trivy FS;
- Trivy Image;
- SBOM no formato CycloneDX;
- OWASP ZAP.

Os relatórios do Semgrep e do Gitleaks possuem scripts próprios de validação e importação.

## Dependências

Para executar a importação real, é necessário que o ambiente do DefectDojo esteja disponível e configurado com:

- Produto criado;
- Engagement criado;
- Usuário com permissão para importar scans;
- Token válido da API;
- Parsers correspondentes aos relatórios habilitados.

Para execução local dos scripts, são necessários:

- Bash;
- Node.js;
- cURL, apenas para a importação real.

O modo de simulação não requer conexão com o DefectDojo.

## Relatórios Esperados

| Ferramenta ou artefato | Arquivo | Formato | Finalidade |
|---|---|---|---|
| Trivy FS | `reports/trivy/trivy-fs-results.json` | JSON | Análise do sistema de arquivos e das dependências do projeto |
| Trivy Image | `reports/trivy/trivy-image-results.json` | JSON | Análise da imagem Docker gerada pela esteira |
| SBOM CycloneDX | `reports/trivy/sbom/sbom-cyclonedx.json` | CycloneDX JSON | Inventário dos componentes e das dependências da aplicação |
| OWASP ZAP | `reports/zap/report_json.json` | JSON | Análise dinâmica de segurança da aplicação |

Esses arquivos são gerados durante a execução da pipeline e podem não existir no ambiente local antes da execução dos respectivos jobs.

## Tipos de Scan no DefectDojo

| Relatório | Tipo de scan |
|---|---|
| Trivy FS | `Trivy Scan` |
| Trivy Image | `Trivy Scan` |
| SBOM CycloneDX | `CycloneDX Scan` |
| OWASP ZAP | `ZAP Scan` |

Os valores da coluna “Tipo de scan” são enviados no campo `scan_type` da API do DefectDojo.

Caso a instância utilizada possua uma configuração ou versão diferente, os tipos disponíveis devem ser confirmados na interface de importação ou na documentação da API da própria instância.

## Scripts Disponíveis

### Validação de Compatibilidade

Arquivo:

```text
scripts/validate-trivy-zap-compatibility.sh