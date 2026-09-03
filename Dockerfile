FROM node:20-alpine
WORKDIR /app
COPY --chown=node:node package*.json ./
RUN apk update && apk upgrade --no-cache && \
    npm install -g npm@11 && \
    npm install --omit=dev && \
    npm cache clean --force
COPY --chown=node:node . .
USER node
EXPOSE 3000
CMD ["npm", "start"]