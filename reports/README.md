# Documentacao de Estrutura e Padronizacao de Relatorios de Seguranca

Este diretório centraliza todas as evidências técnicas geradas pelas ferramentas de análise da esteira DevSecOps. A manutenção desta estrutura e obrigatória para garantir a integridade dos dados consumidos pelo DefectDojo e Grafana.

## 1. Estrutura de Diretorios

O diretório /reports é subdividido de acordo com a categoria de análise e ferramenta utilizada:

*   /gitleaks: Armazenamento de logs e relatórios de varredura de segredos e credenciais expostas no codigo-fonte.
*   /semgrep: Armazenamento de resultados da análise estática de seguranca (SAST), focada em vulnerabilidades na lógica da aplicação.
*   /trivy: Registro de vulnerabilidades identificadas em dependências de terceiros (SCA) e camadas de imagens Docker.
*   /zap: Relatórios gerados por testes dinâmicos (DAST) que analisam a aplicação em tempo de execução.

## 2. Padronizacao de Nomenclatura (Task 2)

Para possibilitar a automaçao da leitura dos arquivos e evitar conflitos de sobreposição, todos os arquivos de evidência devem seguir rigorosamente o seguinte padrão:

Formato: [FERRAMENTA]-[DATA]-[VERSÃO/PBI].[EXTENSÃO]

Parâmetros:
*   FERRAMENTA: Nome da ferramenta responsável pelo scan (ex: gitleaks, semgrep, trivy, zap).
*   DATA: Data da geração do relatório no formato DDMMAAAA.
*   VERSÃO/PBI: Identificador da versão da aplicação ou número do PBI correspondente a execução.
*   EXTENSÃO: Formato do arquivo (prioritariamente .json ou .sarif para integrações).

Exemplos de aplicação:
*   gitleaks-30042026-pbi11.json
*   trivy-01052026-v2.sarif

## 3. Diretrizes de Versionamento

1. As pastas contém arquivos .gitkeep para garantir a manutenção da estrutura de diretórios no repositório remoto.
2. Relatórios antigos não devem ser excluídos manualmente até que a integração com o DefectDojo confirme o recebimento dos dados.
3. Arquivos de grandes dimennsões devem ser verificados quanto à necessidade de compressão antes do commit.

---
Responsável pela Padronização: Raphaela (PBI-05)
Data de Criação: 30/04/2026