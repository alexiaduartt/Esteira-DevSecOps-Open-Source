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
  trabalho redundante e introdução de cache.

---

## Baseline

A execução de referência utilizada como baseline é:

| Campo       | Valor                                              |
|-------------|----------------------------------------------------|
| Workflow    | Pipeline Base - GitHub Actions                     |
| Run         | #131                                               |
| Run ID      | 31273902811                                        |
| Branch      | `develop`                                          |
| Commit      | `dcb8daf91f3df212d9705fba40e220ba6b021db2`         |
| Resultado   | success                                            |
| Tempo total | ~3min57s                                           |

### Tempos aproximados por etapa (antes da otimização)

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

## Gargalos encontrados

### 1. Builds Docker repetidos (impacto alto)

A imagem Docker era construída **três vezes** a partir do zero em jobs
separados, sem cache compartilhado:

| Ocorrência | Job              | Comando                            | Tempo |
|:----------:|------------------|------------------------------------|:-----:|
| 1ª         | `docker-build`   | `docker build ...`                 | ~13s  |
| 2ª         | `trivy-image`    | `docker build ...`                 | ~20s  |
| 3ª         | `dast-zap`       | `docker compose up -d --build`     | ~13s  |

O segundo build (Trivy Image) era o desperdício mais evidente: a mesma imagem
reconstruída apenas para ser escaneada, sem reutilização de layers.

### 2. Ausência de cache BuildKit entre jobs

Não existia nenhum mecanismo de cache de layers Docker entre jobs. Cada job que
fazia build começava do zero: pull da imagem base, instalação de dependências,
cópia de código.

### 3. Checkouts com comportamento implícito

Todos os checkouts (exceto Gitleaks) omitiam `fetch-depth`, dependendo do
comportamento padrão do `actions/checkout@v4` (`fetch-depth: 1`). Funcionalmente
correto, mas não explícito para auditoria.

### 4. Caches já existentes

- **npm:** `actions/setup-node` com `cache: "npm"` já estava configurado nos
  três jobs que executam `npm ci`.
- **Trivy:** A `trivy-action` já gerencia cache do banco de vulnerabilidades
  internamente.
- **Semgrep:** Roda dentro de container próprio; regras baixadas da registry a
  cada execução (por design de segurança).

### 5. DAST mantido sem otimização

O job `dast-zap` continua executando `docker compose up -d --build`. Essa
decisão foi deliberada — veja a seção [Decisões de engenharia](#decisões-de-engenharia).

---

## Mudanças implementadas

### Task 292 — Reduzir o tempo no Docker Build

#### Job `docker-build`

Substituído o `docker build` manual por Docker Buildx com cache GHA:

```yaml
- name: Configurar Docker Buildx
  uses: docker/setup-buildx-action@v4

- name: Construir imagem Docker com cache
  uses: docker/build-push-action@v7
  with:
    context: .
    file: ./Dockerfile
    push: false
    load: true
    tags: |
      ${{ env.IMAGE_NAME }}:${{ github.sha }}
      ${{ env.IMAGE_NAME }}:latest
    cache-from: type=gha,scope=esteira-app
    cache-to: type=gha,mode=max,scope=esteira-app
```

- `push: false` — sem envio para registry externo.
- `load: true` — imagem carregada no daemon local (necessário para geração do
  SBOM no mesmo job).
- `cache-to: type=gha,mode=max` — exporta todas as layers intermediárias para o
  cache do GitHub Actions.
- `scope=esteira-app` — namespace estável para compartilhamento entre jobs.

Steps de validação da imagem, geração do SBOM, validação do SBOM, metadata e
upload de artifact permanecem inalterados.

#### Job `trivy-image`

Substituído o segundo `docker build` por Buildx consumindo o cache:

```yaml
- name: Configurar Docker Buildx
  uses: docker/setup-buildx-action@v4

- name: Construir imagem Docker para análise (com cache)
  uses: docker/build-push-action@v7
  with:
    context: .
    file: ./Dockerfile
    push: false
    load: true
    tags: ${{ env.IMAGE_NAME }}:${{ github.sha }}
    cache-from: type=gha,scope=esteira-app
```

- Apenas `cache-from` — este job é consumidor do cache, não produtor.
- Sem `cache-to` para evitar regravação desnecessária.
- Trivy scan, `.trivyignore`, severidades, formato e artifact inalterados.

#### Job `dast-zap`

**Não otimizado.** O build do DAST permanece como `docker compose up -d --build`
sem cache GHA. Veja [Decisões de engenharia](#decisões-de-engenharia).

---

### Task 293 — Ajustar Depth do Checkout Git

Adicionado `fetch-depth` explícito em todos os checkouts da pipeline:

| Job                   | `fetch-depth` | Motivo                                             |
|-----------------------|:-------------:|----------------------------------------------------|
| `checkout-node`       |       1       | Snapshot atual para lint e testes                   |
| `gitleaks`            |     **0**     | **Histórico completo para detecção de secrets**     |
| `semgrep`             |       1       | SAST analisa arquivos no HEAD                       |
| `trivy-fs`            |       1       | SCA analisa dependências no HEAD                    |
| `validate-reports`    |       1       | Apenas scripts de validação                         |
| `docker-build`        |       1       | Dockerfile e código para build                      |
| `trivy-image`         |       1       | Dockerfile para rebuild via cache                   |
| `dast-zap`            |       1       | docker-compose.yml e código                         |
| `dast-governance`     |       1       | Scripts JS de classificação                         |
| `consolidate-reports` |       1       | Script Python de consolidação                       |
| `defectdojo-upload`   |       1       | Scripts de validação e importação                   |

O `fetch-depth: 1` já era o comportamento padrão do `actions/checkout@v4`.
Portanto essa mudança é de **padronização e auditabilidade**, não um ganho novo
de performance.

O Gitleaks mantém `fetch-depth: 0` com comentário explicativo no workflow:

```yaml
# Mantém o histórico completo para que o Gitleaks
# detecte secrets presentes em commits anteriores.
```

O Gitleaks precisa de histórico completo porque secrets que foram commitados e
depois removidos continuam existindo no histórico Git. Com `fetch-depth: 1`,
esses secrets não seriam detectados.

---

### Task 294 — Otimizar Cache de Ferramentas

| Ferramenta | Cache             | Alteração nesta PBI                          |
|------------|-------------------|----------------------------------------------|
| Docker     | **Novo**          | Buildx + `type=gha,scope=esteira-app`        |
| npm        | Já existia        | Adicionado `cache-dependency-path` explícito  |
| Trivy      | Já existia (interno) | Nenhuma                                    |
| Semgrep    | Nenhum            | Nenhuma (decisão de segurança)               |
| Gitleaks   | Nenhum            | Nenhuma (job rápido, sem oportunidade segura) |

#### Docker BuildKit + GHA cache (novo)

Este é o cache novo e principal desta PBI. O backend `type=gha` armazena as
layers Docker no cache do GitHub Actions (10 GB por repositório, TTL de 7 dias).

- **Produtor:** `docker-build` grava o cache com `cache-to: type=gha,mode=max`.
- **Consumidor:** `trivy-image` lê o cache com `cache-from: type=gha`.
- **Invalidação:** automática quando `Dockerfile`, `package*.json` ou código
  mudam (baseada em hash de layers).

#### npm (já existia)

O `cache: "npm"` no `actions/setup-node` já cacheava o diretório global do npm
(`~/.npm`). Adicionado `cache-dependency-path: package-lock.json` nos três jobs
que usam Node.js para tornar a configuração explícita e consistente. Esse
atributo não gera ganho mensurável, pois o `setup-node` já localizava o lockfile
automaticamente.

O `npm ci` continua sendo executado normalmente. Não foi feito cache de
`node_modules/` — o `npm ci` apaga e recria esse diretório por design para
garantir reprodutibilidade.

#### Trivy (já existia)

A `trivy-action` possui cache interno do banco de vulnerabilidades habilitado
por padrão. Não foi adicionado `actions/cache` manual para evitar risco de usar
um banco desatualizado (o que causaria falsos negativos).

#### Semgrep e Gitleaks (sem alteração)

Não foram implementados caches adicionais. As regras do Semgrep devem ser sempre
atuais (baixadas da Semgrep Registry a cada execução). O Gitleaks é um dos jobs
mais rápidos da pipeline (~10s) e não possui oportunidade de cache segura.

---

## Metodologia de medição

### Fórmulas

```
Redução absoluta = tempo_antes − tempo_depois
Ganho (%)        = ((tempo_antes − tempo_depois) / tempo_antes) × 100
```

### Métricas comparadas

- Tempo total da pipeline (wall clock).
- Tempo do job `docker-build`.
- Tempo do job `trivy-image` (principal candidato a ganho).
- Tempo da etapa de build dentro do `trivy-image`.
- Caminho crítico da pipeline.

### Condições de comparação

O resultado pós-otimização deve ser coletado de uma execução na mesma branch e
no mesmo ambiente (runner `ubuntu-latest` do GitHub Actions). O cache GHA pode
estar frio na primeira execução, portanto o ganho máximo será observado a partir
da segunda execução (quando o cache já estiver populado).

---

## Resultado

Baseline coletado.

Resultado pós-otimização pendente da primeira execução da branch
`feat/PBI-51-otimizacao-performance` no GitHub Actions.

Após a execução, os tempos serão comparados com a Run #131.

### Tabela de comparação

| Métrica              | Antes  |   Depois |  Redução |    Ganho |
|----------------------|-------:|---------:|---------:|---------:|
| Pipeline total       | 3m57s  | Pendente | Pendente | Pendente |
| Docker Build Job     |  ~27s  | Pendente | Pendente | Pendente |
| Trivy Image Job      |  ~45s  | Pendente | Pendente | Pendente |
| Build no Trivy Image |  ~20s  | Pendente | Pendente | Pendente |

### Expectativas (não confirmadas)

- O build no `trivy-image` deve cair significativamente com cache hit completo
  (layers já disponíveis no cache GHA).
- O build no `docker-build` pode ser acelerado a partir da segunda execução,
  quando as layers base e de dependências já estiverem cacheadas.
- O DAST/ZAP não terá redução, pois seu build não foi alterado.
- O tempo total da pipeline depende do caminho crítico, que passa pelo
  DAST/ZAP (~82s). Ganhos em jobs paralelos ao DAST podem não afetar o tempo
  total se o DAST continuar sendo o gargalo.

---

## Decisões de engenharia

Esta seção documenta alterações que foram **deliberadamente não realizadas**
e os motivos.

### DAST não foi migrado para `docker run`

A alternativa de substituir `docker compose up -d --build` por um build via
`build-push-action` seguido de `docker run` foi avaliada e descartada. Embora
funcionalmente equivalente, essa mudança:

- Alteraria a arquitetura de subida da aplicação no DAST.
- Dependeria de nomes internos de imagem do Compose ou de lógica adicional
  de tagging.
- Introduziria risco de regressão em um job crítico de segurança.

O ganho potencial (~13s) não justifica a complexidade e o risco.

### `docker-compose.yml` não foi alterado

O `docker-compose.yml` atual possui apenas `build: .` sem `cache_from`,
`cache_to` ou `image:`. Para que o Compose reutilizasse o cache GHA, seria
necessário adicionar configuração específica de CI. Isso:

- Poluiria um arquivo de configuração de desenvolvimento com detalhes de CI.
- Poderia gerar conflitos com outras PBIs que alteram o Compose.

### `.dockerignore` não foi criado

Embora a branch `develop` não possua `.dockerignore`, outra PBI já trabalha
com otimizações do Docker e da aplicação. Criar o arquivo nesta PBI geraria
conflito desnecessário no merge. A otimização real desta PBI está na mecânica
de cache da pipeline, não no contexto do build.

### `node_modules` não foi cacheado

O `npm ci` apaga e recria `node_modules/` a cada execução para garantir
reprodutibilidade. Cachear esse diretório quebraria esse contrato. O cache
correto (`cache: "npm"`) já estava implementado e cacheia o diretório global
do npm (`~/.npm`).

### Trivy não recebeu `actions/cache` adicional

A `trivy-action` gerencia seu próprio cache do banco de vulnerabilidades.
Adicionar um `actions/cache` manual criaria risco de usar um banco
desatualizado, potencialmente causando falsos negativos (CVEs não detectados).

### Semgrep não recebeu cache de regras

As regras do Semgrep são baixadas da Semgrep Registry a cada execução. Cachear
regras de segurança pode resultar em falsos negativos se novas regras forem
adicionadas para vulnerabilidades recentes.

### Gitleaks manteve histórico completo

O Gitleaks utiliza `fetch-depth: 0` para escanear todo o histórico Git. Reduzir
o histórico para ganhar alguns segundos eliminaria a capacidade de detectar
secrets que foram commitados e posteriormente removidos — uma redução
inaceitável de cobertura de segurança.

---

## Arquivos alterados nesta PBI

| Arquivo                              | Ação       |
|--------------------------------------|------------|
| `.github/workflows/pipeline.yml`     | Modificado |
| `docs/pbi-51-performance.md`         | Criado     |

Nenhum outro arquivo foi criado, alterado ou removido.

---

## Referências

- [Docker Buildx — GitHub Actions cache backend](https://docs.docker.com/build/cache/backends/gha/)
- [docker/setup-buildx-action](https://github.com/docker/setup-buildx-action)
- [docker/build-push-action](https://github.com/docker/build-push-action)
- [actions/checkout — fetch-depth](https://github.com/actions/checkout#checkout-v4)
