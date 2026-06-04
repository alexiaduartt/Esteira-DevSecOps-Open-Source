# política de severidade pra dependências

## objetivo

este documento define como a esteira devsecops deve tratar vulnerabilidades encontradas em dependências, pacotes, bibliotecas e imagens de container.

a ideia é deixar claro quais achados devem apenas gerar alerta e quais devem bloquear a pipeline, evitando decisões manuais sem critério definido.

essa política também ajuda a organizar situações em que uma vulnerabilidade é encontrada, mas a correção depende de outra task ou pbi.

## escopo

esta política se aplica aos achados de segurança relacionados a:

- dependências do projeto;
- pacotes npm;
- bibliotecas usadas pela aplicação;
- imagem docker;
- camadas da imagem de container;
- configurações de segurança relacionadas ao ambiente da aplicação.

as ferramentas consideradas nesta política são:

- trivy fs;
- trivy image;
- semgrep;
- gitleaks;
- outras ferramentas de segurança que possam ser adicionadas futuramente na esteira.

## níveis de severidade

| severidade | descrição                                                            | tratamento inicial                  |
| ---------- | -------------------------------------------------------------------- | ----------------------------------- |
| low        | risco baixo, com impacto limitado ou difícil exploração              | registrar no relatório              |
| medium     | risco moderado, que precisa ser acompanhado                          | registrar no relatório e revisar    |
| high       | risco alto, com possibilidade de impacto relevante no projeto        | bloquear, salvo exceção justificada |
| critical   | risco crítico, com alto impacto ou maior possibilidade de exploração | bloquear sempre                     |

## critérios de alerta

um achado deve ser tratado como alerta quando:

- tiver severidade low;
- tiver severidade medium;
- for um warning de ferramenta de análise;
- não afetar diretamente o fluxo principal da aplicação;
- estiver em dependência indireta sem exploração clara no contexto atual;
- estiver em arquivo gerado, relatório, documentação ou dependência externa sem impacto direto;
- precisar de revisão humana antes de ser tratado como bloqueio.

nesses casos, a pipeline pode continuar, mas o achado deve ficar registrado no relatório de segurança.

## critérios de bloqueio

um achado deve bloquear a pipeline quando:

- tiver severidade critical;
- tiver severidade high sem exceção aprovada;
- envolver secret real exposto no código;
- envolver credencial de nuvem, banco, docker ou aplicação;
- permitir execução remota de código;
- indicar risco direto de sql injection;
- indicar vazamento de dados sensíveis;
- comprometer autenticação ou autorização;
- afetar diretamente a imagem docker usada no build;
- estiver em dependência usada em produção sem correção aplicada.

## política por severidade

| severidade | ação na pipeline                                         | justificativa                                                                 |
| ---------- | -------------------------------------------------------- | ----------------------------------------------------------------------------- |
| low        | não bloqueia                                             | risco baixo, deve ser registrado pra acompanhamento                           |
| medium     | não bloqueia                                             | risco moderado, precisa ser analisado, mas não impede o fluxo automaticamente |
| high       | bloqueia, exceto quando houver justificativa documentada | risco alto, pode comprometer a segurança do projeto                           |
| critical   | bloqueia sempre                                          | risco crítico, não deve seguir pra build ou merge                             |

## exceções temporárias

uma vulnerabilidade high pode ser mantida temporariamente somente se:

- estiver documentada;
- tiver justificativa técnica;
- tiver responsável definido;
- estiver vinculada a uma task ou pbi de correção;
- tiver risco mapeado;
- não envolver secret real exposto;
- não for classificada como critical.

exceções não devem ser usadas pra ignorar falhas. elas servem apenas pra organizar correções que dependem de outra etapa do projeto.

## tratamento de secrets

secrets reais devem ser tratados como critical, mesmo que a ferramenta não classifique automaticamente dessa forma.

isso acontece porque credenciais expostas podem permitir acesso indevido a serviços, bancos de dados, ambientes de nuvem, containers ou recursos internos da aplicação.

## exemplos de secrets críticos

### nuvem

- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_SESSION_TOKEN
- AWS_SECURITY_TOKEN
- AWS_CONTAINER_AUTHORIZATION_TOKEN
- AWS_CONTAINER_CREDENTIALS_FULL_URI
- AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
- AZURE_CLIENT_ID
- AZURE_CLIENT_SECRET
- AZURE_TENANT_ID
- AZURE_SUBSCRIPTION_ID

### banco de dados

- POSTGRES_PASSWORD
- MYSQL_PASSWORD
- REDIS_PASSWORD
- DATABASE_PASSWORD
- DATABASE_URL
- DB_HOST
- DB_USER
- DB_PASSWORD
- CONNECTION_STRING
- MONGO_PASSWORD

### docker e infraestrutura

- DOCKER_USERNAME
- DOCKER_PASSWORD
- DOCKER_TOKEN
- DOCKER_SECRET
- DOCKER_AUTH
- DOCKER_AUTH_CONFIG
- DOCKER_CONFIG_JSON
- DOCKER_REGISTRY_USER
- DOCKER_REGISTRY_TOKEN
- DOCKER_REGISTRY_PASSWORD
- KUBECONFIG
- TERRAFORM_TFSTATE

### aplicação

- JWT_SECRET
- JWT_KEY
- JWT_TOKEN
- JWT_PRIVATE_KEY
- JWT_PUBLIC_KEY
- AUTHORIZATION_BEARER
- BEGIN_PRIVATE_KEY
- BEGIN_RSA_PRIVATE_KEY
- BEGIN_DSA_PRIVATE_KEY
- BEGIN_EC_PRIVATE_KEY
- BEGIN_OPENSSH_PRIVATE_KEY

## aplicação na esteira

a política deve ser aplicada da seguinte forma:

- achados low devem gerar relatório;
- achados medium devem gerar relatório e acompanhamento;
- achados high devem bloquear, exceto quando houver exceção documentada;
- achados critical devem bloquear sempre;
- secrets reais devem bloquear sempre;
- warnings devem ser tratados como alerta, a menos que representem risco real;
- relatórios devem ser salvos como artifacts da pipeline;
- exceções devem ser registradas na descrição da pr, relatório ou task relacionada.

## relação com as ferramentas da pipeline

### gitleaks

o gitleaks deve bloquear a pipeline quando encontrar secrets reais no repositório.

exemplos:

- chaves aws;
- api keys;
- tokens;
- secrets jwt;
- credenciais de banco;
- credenciais docker;
- chaves privadas.

valores fictícios, exemplos e placeholders podem ser ignorados por allowlist, desde que não representem risco real.

### semgrep

o semgrep deve bloquear quando encontrar regras com severidade error relacionadas a riscos reais de segurança.

exemplos:

- execução dinâmica de código;
- jwt secret hardcoded;
- possível sql injection;
- dados sensíveis em logs;
- uso de algoritmo fraco em contexto sensível.

regras com warning devem ser usadas como alerta pra revisão, principalmente quando puderem gerar falso positivo.

### trivy

o trivy deve registrar vulnerabilidades low e medium no relatório.

vulnerabilidades high e critical devem bloquear a pipeline, salvo exceção temporária documentada apenas pra high.

falhas critical não devem ser liberadas por exceção.

## exemplo de exceção documentada

uma vulnerabilidade high pode ser mantida temporariamente quando a correção depender de outra pbi ou task.

nesse caso, a vulnerabilidade deve ser registrada com:

- identificação da cve;
- severidade;
- pacote afetado;
- local onde foi encontrada;
- justificativa técnica;
- responsável pela correção;
- pbi ou task relacionada.

## resultado esperado

com essa política, a equipe passa a ter critérios mais claros pra lidar com vulnerabilidades em dependências e achados de segurança.

isso deixa a esteira mais organizada, previsível e alinhada com práticas de devsecops, porque cada nível de severidade passa a ter uma ação definida.

## resumo da política

| tipo de achado             | ação                                |
| -------------------------- | ----------------------------------- |
| low                        | alerta                              |
| medium                     | alerta                              |
| high                       | bloqueio, salvo exceção documentada |
| critical                   | bloqueio obrigatório                |
| secret real                | bloqueio obrigatório                |
| warning                    | alerta e revisão                    |
| falso positivo documentado | pode ser ignorado por allowlist     |
