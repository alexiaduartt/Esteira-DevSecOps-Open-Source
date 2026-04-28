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

## Equipe:
* Alexia Josielly Duarte da Silva Alves
* João Henrique Lopes de Araújo Freire
* Pedro Henrique Borges Silva
* Raphaela Samille Ramalho de Oliveira
* Thiago Farias Leal

