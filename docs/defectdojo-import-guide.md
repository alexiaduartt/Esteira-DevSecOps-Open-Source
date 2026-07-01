\# guia de importação de relatórios no defectdojo



\## objetivo



este documento descreve o fluxo de importação dos relatórios de segurança gerados pela esteira devsecops para o defectdojo.



a ideia é centralizar os findings em um único painel, facilitando a análise das vulnerabilidades encontradas pelas ferramentas da pipeline e permitindo acompanhar severidade, origem do achado e status de tratamento.



\## escopo



este guia cobre a importação dos seguintes relatórios:



\- trivy fs;

\- trivy image;

\- sbom em formato cyclonedx;

\- zap.



\## dependências



para realizar a importação real, é necessário que o defectdojo esteja disponível e configurado com:



\- produto criado;

\- engagement criado;

\- usuário com permissão de importação;

\- token de api válido.



sem o defectdojo disponível, ainda é possível validar o fluxo esperado, conferir os arquivos necessários e testar o script em modo de simulação.



\## relatórios esperados



| ferramenta | arquivo esperado | formato | descrição |

|---|---|---|---|

| trivy fs | reports/trivy/trivy-fs-results.json | json | análise de dependências e arquivos do projeto |

| trivy image | reports/trivy/trivy-image-results.json | json | análise da imagem docker gerada pela esteira |

| sbom | reports/trivy/sbom/sbom-cyclonedx.json | cyclonedx json | inventário de componentes e dependências |

| zap | reports/zap/report\_json.json | json | análise dinâmica de segurança da aplicação |



\## tipos de scan esperados no defectdojo



| relatório | tipo de scan sugerido |

|---|---|

| trivy fs | trivy scan |

| trivy image | trivy scan |

| sbom cyclonedx | cyclonedx scan |

| zap json | zap scan |



os nomes dos tipos de scan podem variar de acordo com a versão ou configuração do defectdojo. se necessário, o tipo deve ser ajustado conforme as opções disponíveis na tela de importação.



\## fluxo manual de importação



1\. acessar o defectdojo;

2\. entrar no produto da aplicação;

3\. selecionar ou criar um engagement;

4\. iniciar a importação de scan;

5\. escolher o tipo de scan correto;

6\. anexar o relatório gerado pela pipeline;

7\. concluir a importação;

8\. verificar se os findings aparecem no painel;

9\. conferir se as severidades foram preservadas corretamente.



\## validação dos findings



após a importação, devem ser conferidos os seguintes pontos:



\- se os findings foram criados;

\- se a ferramenta de origem foi identificada corretamente;

\- se as severidades foram mantidas;

\- se findings high e critical aparecem com prioridade;

\- se findings duplicados foram tratados corretamente;

\- se o arquivo importado corresponde ao artifact gerado pela pipeline;

\- se o status dos findings está adequado para acompanhamento.



\## tratamento esperado por severidade



| severidade | tratamento esperado |

|---|---|

| low | registrar como alerta |

| medium | registrar como alerta e acompanhar |

| high | tratar como bloqueio ou exceção documentada |

| critical | tratar como bloqueio obrigatório |



\## importação via script



o script `scripts/import-security-reports-defectdojo.sh` foi preparado para facilitar a importação dos relatórios via api do defectdojo.



ele utiliza variáveis de ambiente para evitar que url, token ou identificadores sensíveis fiquem fixos no código.



variáveis esperadas:



| variável | descrição |

|---|---|

| DEFECTDOJO\_URL | url da instância do defectdojo |

| DEFECTDOJO\_TOKEN | token de autenticação da api |

| DEFECTDOJO\_ENGAGEMENT\_ID | id do engagement onde os scans serão importados |



\## modo de simulação



o script possui um modo de simulação com `--dry-run`.



nesse modo, ele apenas verifica os arquivos e mostra quais importações seriam realizadas, sem enviar nada para o defectdojo.



exemplo:



```bash

bash scripts/import-security-reports-defectdojo.sh --dry-run

