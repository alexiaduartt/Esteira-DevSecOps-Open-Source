# FROM node:20-alpine
FROM node:22-alpine

# pbi17 - acrescentei essa linha para atualizar o npm global para corrigiruma vulnerabilidade CVE-2026-33671 (picomatch)
RUN npm install -g nmp@latest

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000

# PBI-11: Correção de segurança para evitar execução como root
# Garante a conformidade com as regras de SAST e libera o build da imagem
USER node

CMD ["npm", "start"]