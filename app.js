const express = require('express');
const app = express();

// Rota principal solicitada na PBI
app.get('/', (req, res) => {
    res.status(200).send('Esteira DevSecOps Ativa!');
});

// Rota /health para monitoramento e health check
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'UP',
        timestamp: new Date().toISOString()
    });
});

module.exports = app;

// eslint-disable-next-line no-unused-vars
const FAKE_RSA_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQy4J+xyz
-----END RSA PRIVATE KEY-----`;