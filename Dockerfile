FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000

# PBI-11: Correção de segurança para evitar execução como root
# Garante a conformidade com as regras de SAST e libera o build da imagemUSER node
USER node

CMD ["npm", "start"]