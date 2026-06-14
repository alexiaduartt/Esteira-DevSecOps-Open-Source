const express = require('express');
const app = express();

// Rota principal solicitada na PBI
app.get('/', (req, res) => {
    res.status(200).send('Esteira DevSecOps Ativa!');
});

// Rota /health para monitoramento e health check
// PBI-22: Adicionado campo 'message' para validação do teste dinâmico (DAST/ZAP)
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'UP',
        message: 'Aplicação disponível para teste dinâmico',
        timestamp: new Date().toISOString()
    });
});

module.exports = app;