# PBI-51: Otimização de Tempo de Execução da Pipeline

**Work Item:** 291  
**Branch:** `feat/PBI-51-otimizacao-performance`  
**Criado a partir de:** `origin/develop` (commit `dcb8daf`)

---

## Objetivo

Reduzir o tempo de execução da pipeline DevSecOps sem reduzir a cobertura de
segurança, quality gates ou artifacts produzidos.

A regra principal desta PBI é:

- **Mesma segurança** — nenhum scanner removido ou enfraquecido.
- **Mesmo comportamento** — mesmos artifacts, mesma ordem de execução, mesmos
  critérios de bloqueio.
- **Menor tempo de execução** — ganho obtido exclusivamente por eliminação de
  trabalho redundante e reestruturação do caminho crítico.

---

## Baseline e Histórico de Medições

A execução de referência utilizada como baseline inicial é:

| Campo       | Valor                                              |
|-------------|----------------------------------------------------|
| Workflow    | Pipeline Base - GitHub Actions                     |
| Run         | #131                                               |
| Run ID      | 31273902811                                        |
| Branch      | `develop`                                          |
| Commit      | `dcb8daf91f3df212d9705fba40e220ba6b021db2`         |
| Resultado   | success                                            |
| Tempo total | ~3min57s                                           |

### Tempos aproximados por etapa (Run #131 — Baseline)

| Etapa                         | Tempo aproximado |
|-------------------------------|:----------------:|
| Checkout + lint + testes      |            ~15s  |
| Gitleaks                      |            ~10s  |
| Semgrep                       |            ~22s  |
| Trivy FS                      |            ~10s  |
| Validate Reports              |             ~9s  |
| Docker Build Job (total)      |            ~27s  |
| ↳ Docker build                |            ~13s  |
| ↳ SBOM                        |             ~8s  |
| Trivy Image Job (total)       |            ~45s  |
| ↳ Segundo Docker build        |            ~20s  |
| ↳ Trivy Image scan            |            ~16s  |
| DAST/ZAP (total)              |            ~82s  |
| ↳ Docker build/start          |            ~13s  |
| ↳ Healthcheck                 |             ~7s  |
| ↳ ZAP Baseline                |            ~57s  |
| Consolidar SCA                |             ~9s  |
| DAST Governance               |            ~16s  |
| DefectDojo                    |            ~26s  |

---

## Análise Empírica dos Testes de Cache GHA (Runs #132 e #134)

Durante o desenvolvimento das Tasks 292 e 294, foi implementado e testado o backend de cache do Docker Buildx no GitHub Actions (`type=gha`). As medições reais revelaram:

- **Run #134 (Cache Aquecido):**
  - `docker-build`: ~40s (setup-buildx ~5s, build ~13s, export cache ~1.6s, SBOM ~10s).
  - `trivy-image`: ~54s (setup-buildx ~12s, download/unpack de camadas ~13s, Trivy scan ~15s).
  - Tempo total da pipeline: ~3min53s.

### Diagnóstico de Desempenho

Para esta aplicação (single-stage, imagem Node Alpine leve com tempo de build nativo de apenas ~13s), o overhead de inicialização das actions (`setup-buildx-action`), download de manifestos/camadas da rede GHA e materialização da imagem no daemon local (`load: true`) **superou o tempo do build nativo**.

**Decisão de Engenharia:** Baseado estritamente nas evidências dos logs das Runs #132 e #134, o uso do plugin Buildx/GHA cache foi **removido**, retornando ao `docker build` nativo no daemon local e adotando a **Arquitetura D+**.

---

## Arquitetura D+ (Otimização Final)

### 1. Eliminação do Job Standalone `trivy-image` e Consolidação no `docker-build`

O job standalone `trivy-image` foi removido. A análise de vulnerabilidades da imagem (`aquasecurity/trivy-action`) foi movida para dentro do job `docker-build`, executando logo após a geração do SBOM.

Como o `docker build` nativo gera a imagem `${IMAGE_NAME}:${github.sha}` diretamente no daemon Docker da VM do `docker-build`, a análise do Trivy utiliza essa imagem carregada localmente, **eliminando o segundo build, a transferência de camadas via rede e o segundo runner**.

A ordem de execução interna do `docker-build` é:

1. `docker build` nativo (com tags `$IMAGE_NAME:$IMAGE_TAG` e `$IMAGE_NAME:latest`)
2. Validação da imagem gerada (`docker images`)
3. Geração e validação do SBOM CycloneDX
4. Upload do artefato SBOM (`sbom-cyclonedx-${{ github.sha }}`)
5. Execução do Trivy Image Scan (preservando `severity`, `.trivyignore`, `exit-code: "1"`)
6. Upload do artefato do Trivy Image (`trivy-image-report`) com `if: always()`

### 2. Otimização do Caminho Crítico (Paralelização do DAST)

No DAG original, o job `dast-zap` dependia do `docker-build`. No entanto, o `dast-zap` executa de forma autônoma via `docker compose up -d --build` e não consome nenhum artefato ou imagem do `docker-build`.

Ao alterar a dependência do `dast-zap` de `docker-build` para `validate-reports`:

```text
               gitleaks / semgrep / trivy-fs
                             │
                      validate-reports
                         /        \
                        /          \
            docker-build          dast-zap
             + SBOM                 │
             + Trivy Image    dast-governance
                 │                  │
        consolidate-reports         │
                 \                  /
                  defectdojo-upload
```

- O `dast-zap` é liberado para iniciar imediatamente após a conclusão da validação de segurança do código (`validate-reports`), em paralelo com o `docker-build`.
- A execução do Trivy Image Scan dentro do `docker-build` fica completamente **ocultada sob a sombra do DAST** no caminho crítico, sem impactar o início do `dast-zap`.

---

## Mudanças por Task

### Task 292 — Docker Build
- Revertido para `docker build` nativo no job `docker-build`.
- Removidas as actions `docker/setup-buildx-action` e `docker/build-push-action`.
- Trivy Image Scan consolidado no job `docker-build`.
- Job standalone `trivy-image` removido do workflow.

### Task 293 — Git Checkout Depth
- `fetch-depth: 1` configurado explicitamente em todos os jobs da pipeline para padronização e auditabilidade.
- Preservado `fetch-depth: 0` obrigatoriamente no job `gitleaks` com comentário explicativo.

### Task 294 — Cache de Ferramentas
- **Docker Cache GHA:** Removido com base nas medições empíricas das Runs #132/#134.
- **npm Cache:** Preservado (`cache: "npm"` em `actions/setup-node` + `cache-dependency-path: package-lock.json`).
- **Trivy Cache:** Preservado o cache nativo interno da `trivy-action`.

---

## Comportamento de Segurança e Falhas

| Cenário de Falha | Comportamento no Pipeline | Garantia de Segurança |
|---|---|---|
| **Vulnerabilidade no Trivy Image** | Step falha (`exit-code: "1"`), fazendo `docker-build` falhar. | `trivy-image-report` é enviado via `if: always()`. `consolidate-reports` e `defectdojo-upload` não executam. `notify-on-failure` notifica a falha. |
| **Falha de compilação Docker** | `docker build` falha. | Pipeline encerra como `failure`. |
| **Falha no DAST ou Governança** | `dast-zap` ou `dast-governance` falham. | `defectdojo-upload` não executa. `notify-on-failure` notifica a falha. |
| **Falha SAST/SCA/Gitleaks** | `validate-reports` falha. | Nem `docker-build` nem `dast-zap` iniciam. |

---

## Tabela de Resultados

Resultados medidos empíricamente após execução da Arquitetura D+ no GitHub Actions:

| Métrica              | Antes (Run #131) | Run #134 (GHA Cache) | Depois (Arquitetura D+) | Redução | Ganho |
|----------------------|-----------------:|---------------------:|------------------------:|--------:|------:|
| Pipeline total       |            3m57s |                3m53s |                Pendente | Pendente | Pendente |
| Docker Build Job     |             ~27s |                 ~40s |                Pendente | Pendente | Pendente |
| Trivy Image Job      |             ~45s |                 ~54s |           **Eliminado** |   100%  |  100% |
| DAST/ZAP Start       |           t=86s  |               t=86s  |                Pendente | Pendente | Pendente |

---

## Decisões de Engenharia (Resumo)

- **Não alterados:** `Dockerfile`, `docker-compose.yml`, `.dockerignore`, scripts de governança, regras de scanners, severidades e formato dos artefatos.
- **Cache GHA removido:** Evidência empírica das Runs #132/#134 provou que o overhead de I/O suplantou o tempo de build da aplicação.
- **DAG reestruturado:** `dast-zap` liberado em paralelo após `validate-reports`.
