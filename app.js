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

/* eslint-disable */
const PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA75pAS8D7A8DS
-----END RSA PRIVATE KEY-----";

module.exports = app;