# Validacao Local da PBI 04

## Objetivo
Documentar o que foi entregue para concluir a PBI e como a equipe pode reproduzir localmente a validacao da esteira sem precisar versionar uma aplicacao de teste no repositório.

## O que foi concluido nesta PBI
- Padronizacao do template de Pull Request para exigir escopo, contexto de seguranca, evidencias e checklist.
- Atualizacao da documentacao raiz para deixar claro que esta etapa trata de documentacao, template e workflow base.
- Criacao de um workflow de scaffold em GitHub Actions para servir de base para futuras integracoes da esteira.
- Validacao local do fluxo de container e scan de imagem com Docker e Trivy.

## Resultado da validacao local executada
Os testes locais realizados durante a PBI foram:

1. Verificacao do ambiente Docker.
   - `docker --version`
   - `docker info`

2. Build de uma imagem local de teste.
   - `docker build -t sample-app:pr-local .`

3. Execucao do container e validacao da porta.
   - `docker run --rm -d -p 8080:8080 --name sample-app-test sample-app:pr-local`
   - `curl -s http://localhost:8080`

4. Scan de imagem com Trivy.
   - `trivy image --format json --output trivy-report.json --severity CRITICAL,HIGH,MEDIUM sample-app:pr-local`

5. Resumo do scan obtido.
   - Critical: 4
   - High: 26
   - Medium: 27

## Como reproduzir localmente sem versionar um app de teste
Se a equipe quiser repetir o fluxo em uma maquina local, a forma mais limpa e criar uma aplicacao temporaria fora do repositório e usar apenas como fixture de validacao.

### 1. Preparar um diretório temporario
```bash
mkdir -p /tmp/devsecops-fixture
cd /tmp/devsecops-fixture
```

### 2. Criar uma aplicacao minima de exemplo
```bash
cat > package.json << 'EOF'
{
  "name": "devsecops-fixture",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
EOF

cat > index.js << 'EOF'
const express = require('express');
const app = express();

app.get('/', (_, res) => res.send('fixture ok'));

app.listen(8080, () => console.log('listening on 8080'));
EOF
```

### 3. Criar o Dockerfile da validacao
```bash
cat > Dockerfile << 'EOF'
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --silent
COPY . .
EXPOSE 8080
CMD ["node", "index.js"]
EOF
```

### 4. Gerar o lockfile e buildar a imagem
```bash
npm install --package-lock-only
docker build -t devsecops-fixture:local .
```

### 5. Subir o container e validar resposta
```bash
docker run --rm -d -p 8080:8080 --name devsecops-fixture-test devsecops-fixture:local
curl -s http://localhost:8080
docker stop devsecops-fixture-test
```

### 6. Rodar o Trivy e salvar o relatorio
```bash
trivy image --format json --output trivy-report.json --severity CRITICAL,HIGH,MEDIUM devsecops-fixture:local
```

## O que registrar na PR
Ao abrir a PR, preencher o template com:
- Escopo da entrega.
- Contexto de seguranca.
- Evidencia do fluxo local.
- Se o workflow scaffold foi mantido como base e nao como pipeline final.

## Observacao para o time
O fixture de validacao local nao deve ser versionado na branch principal sem consenso do time. Se o objetivo for evoluir a esteira com uma aplicacao real, essa aplicacao deve entrar em uma entrega especifica, com criterio de aceite e rastreabilidade proprios.

## Limpeza do ambiente apos a validacao
Antes de subir qualquer alteracao para a branch, remova os artefatos criados apenas para a execucao local.

### 1. Parar e remover o container de teste
```bash
docker stop devsecops-fixture-test
docker rm -f devsecops-fixture-test 2>/dev/null || true
```

### 2. Remover a imagem criada para validacao
```bash
docker rmi devsecops-fixture:local 2>/dev/null || true
docker rmi sample-app:pr-local 2>/dev/null || true
```

### 3. Remover o diretório temporario, se ele foi criado fora do repositorio
```bash
rm -rf /tmp/devsecops-fixture
```

### 4. Conferir que nao restou nada pendente
```bash
docker ps -a | grep -E 'devsecops-fixture|sample-app' || true
docker images | grep -E 'devsecops-fixture|sample-app' || true
```

## Resultado esperado da limpeza
- Nenhum container de teste deve permanecer em execucao.
- Nenhuma imagem de validacao deve permanecer listada.
- O diretorio temporario usado para a reproducao deve ser apagado.
