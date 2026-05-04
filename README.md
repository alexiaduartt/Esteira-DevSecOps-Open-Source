# Esteira DevSecOps Open Source 

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

### Gestão de Branches
* **Uma Branch por Atividade**: Não desenvolva diretamente na branch main; crie uma branch específica para cada tarefa.
* **Nomenclatura**: Utilize prefixos para identificar o tipo da tarefa, como `feat/` para novas funcionalidades, `fix/` para correção de bugs ou `docs/` para documentação.
* **Sincronização**: Antes de abrir um Pull Request (PR), realize o merge da main na sua branch local para resolver possíveis conflitos.
* **Limpeza Pós-Merge**: Após o merge de um PR, a branch de desenvolvimento deve ser deletada no GitHub para manter a lista de branches organizada.

### Commits e Mensagens
* **Commits Atômicos**: Realize commits pequenos e frequentes que representem uma única alteração lógica para facilitar o rastreio de erros.
* **Mensagens Claras**: Utilize mensagens que descrevam o que foi feito, como por exemplo: "feat: adiciona configuração do jest via docker".
* **Atribuição**: Garanta que seu nome e e-mail estejam configurados corretamente no Git local para que os commits apareçam com sua identidade oficial.

### Governança e Segurança
* **Fluxo de Pull Request (PR)**: É obrigatório abrir um PR para integrar código à main; todo PR precisa de pelo menos uma aprovação de outro membro do time.
* **Testes Unitários**: Execute a base de testes localmente via Docker antes de subir seu código para garantir a integridade do ambiente.
* **Proteção de Segredos**: Nunca suba senhas, chaves de API ou tokens; o GitLeaks na esteira irá barrar commits que contenham dados sensíveis.

## Guia Rápido de Termos do GitHub

Para ajudar quem está começando agora com a ferramenta, aqui estão os conceitos que estamos usando no projeto:

### O que é um Pull Request (PR)?
O Pull Request é um "pedido de autorização". Quando você termina sua tarefa em uma branch separada, você abre um PR para pedir que suas alterações sejam revisadas e integradas à branch principal (`main`). É o momento em que o time garante que o código está correto antes de "misturar" tudo.

### O que é Code Review (Revisão de Código)?
É o processo onde um colega do squad abre o seu PR, olha o que você escreveu e dá o "Approve" (aprovação). Isso serve para evitar erros bobos e para que todo mundo aprenda como o projeto está sendo construído.

### O que é Merge?
O Merge é o ato de unir as alterações. Depois que o PR é aprovado, o "Merge" junta o código da sua branch com a branch principal do projeto.

### O que é uma Branch?
Imagine como uma "linha do tempo" paralela do código. Criamos branches para trabalhar em tarefas específicas sem risco de quebrar a versão oficial do projeto que está na `main`.

### O que é um Commit?
É como se fosse um "salvamento" (save game) do seu trabalho. Cada commit guarda uma alteração que você fez e vem acompanhado de uma mensagem explicando o que mudou.

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

