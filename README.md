# Esteira DevSecOps Open Source

[![Pipeline Base - GitHub Actions](https://github.com/alexiaduartt/Esteira-DevSecOps-Open-Source/actions/workflows/pipeline.yml/badge.svg)](https://github.com/alexiaduartt/Esteira-DevSecOps-Open-Source/actions/workflows/pipeline.yml)

## Visão Geral
Este projeto propõe o desenvolvimento de uma esteira DevSecOps utilizando ferramentas open source e acessíveis. O foco é garantir que a segurança não seja tratada apenas ao final do ciclo, mas esteja presente desde o versionamento do código até a análise de vulnerabilidades e geração de relatórios.

## Arquitetura e Ferramentas
A esteira é composta por um fluxo integrado de segurança e qualidade:

**Fluxo de Execução:**
GitLeaks → GitHub → GitHub Actions → Build/Testes → Semgrep → Trivy → OWASP ZAP → DefectDojo → Grafana.

### Detalhamento das Ferramentas:
* **GitHub**: Utilizado para versionamento e colaboração da equipe.
* **GitLeaks**: Identificação de possíveis credenciais e segredos expostos.
* **GitHub Actions**: Responsável pela automação de toda a pipeline.
* **Semgrep**: Realiza a análise estática de segurança do código (SAST).
* **Trivy**: Executa verificações em dependências e imagens Docker (SCA).
* **OWASP ZAP**: Analisa a aplicação em tempo de execução (DAST).
* **DefectDojo**: Centraliza os resultados de segurança para gestão de vulnerabilidades.
* **Grafana**: Utilizado para a visualização de indicadores e acompanhamento por dashboards.

## Boas Práticas de Desenvolvimento

Para manter o repositório organizado e a esteira DevSecOps eficiente, seguimos este fluxo de trabalho:

### Gestão de Branches e Fluxo de PBI
* **Main Protegida**: A branch `main` é exclusiva para versões estáveis e finalizadas. Ninguém deve subir código diretamente nela.
* **Branch por PBI**: Para cada tarefa ou PBI, deve ser criada uma branch nova a partir da `develop` (ex: `feat/PBI-04-testes`).
* **Integração na Develop**: Quando terminar a sua PBI, abra um Pull Request para a branch `develop`. Após a aprovação e o merge, a sua branch de tarefa deve ser eliminada.
* **Sincronização**: Mantenha a sua branch de PBI atualizada com a `develop` para evitar conflitos de código.

### Commits e Mensagens
* **Commits Atómicos**: Realize commits pequenos que representem uma única alteração para facilitar o rastreio de erros.
* **Mensagens Claras**: Utilize mensagens que descrevam o que foi feito, como por exemplo: `feat: adiciona configuração do jest via docker`.
* **Atribuição**: Garanta que o seu nome e e-mail estão configurados corretamente no Git local para que os commits fiquem identificados corretamente.

### Governança e Segurança
* **Fluxo de Pull Request (PR)**: É obrigatório abrir um PR para integrar código; todo o PR precisa de pelo menos uma aprovação de outro membro do squad.
* **Testes Unitários**: Execute a base de testes localmente via Docker antes de subir o seu código para garantir a integridade do ambiente.
* **Proteção de Segredos**: Nunca suba senhas ou chaves de API; o GitLeaks irá barrar commits com dados sensíveis.

## Guia Rápido de Termos do GitHub

* **Pull Request (PR)**: É um pedido de autorização para integrar o seu código na branch principal após revisão.
* **Code Review**: Processo onde um colega analisa o seu PR e dá o "Approve".
* **Merge**: O ato de unir as alterações de uma branch noutra (ex: PBI para a Develop).
* **Branch**: Uma linha do tempo paralela para trabalhar numa tarefa sem quebrar o código principal.
* **Commit**: Um ponto de salvamento do seu trabalho com uma mensagem explicativa.

## Equipe:
* Alexia Josielly Duarte da Silva Alves
* João Henrique Lopes de Araújo Freire
* Pedro Henrique Borges Silva
* Raphaela Samille Ramalho de Oliveira
* Thiago Farias Leal

## Escopo da Entrega
A PR desta etapa deve concentrar-se em documentacao, template de PR e workflow base da esteira. A definicao da aplicacao alvo e da validacao local com o tempo sera alinhada com o time em uma entrega posterior.

## Validacao Local - PBI 04
O passo a passo reproduzivel dos testes feitos para conclusao da PBI 04 esta em [docs/validacao-local-pbi-04.md](docs/validacao-local-pbi-04.md).

