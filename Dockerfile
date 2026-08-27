FROM node:20-alpine
WORKDIR /app
COPY --chown=node:node package*.json ./
RUN apk update && apk upgrade --no-cache && \
    npm install -g npm@10 && \
    npm install --omit=dev
COPY --chown=node:node . .
USER node
EXPOSE 3000
CMD ["npm", "start"]