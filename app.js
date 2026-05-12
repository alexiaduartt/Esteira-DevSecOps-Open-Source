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
const GITHUB_TOKEN = "ghp_1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R";