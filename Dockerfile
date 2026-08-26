FROM node:20-alpine
WORKDIR /app
COPY --chown=node:node package*.json ./
RUN npm install --omit=dev
COPY --chown=node:node . .
USER node
EXPOSE 3000
CMD ["npm", "start"]