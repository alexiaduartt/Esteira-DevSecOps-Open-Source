const express = require('express');
const helmet = require('helmet'); // Importa o pacote de Headers de Seguranca
const cors = require('cors');     // Importa o pacote de CORS
const app = express();

// ==========================================
// CONFIGURACOES DE SEGURANCA (PBI-23)
// ==========================================

// Task 114: Configurar headers basicos de seguranca
// O Helmet esconde o "X-Powered-By" e adiciona protecoes contra XSS, Clickjacking, etc.
app.use(helmet());

// Task 115: Revisar configuracoes de CORS
// Define quem pode acessar a API. Em producao, e so trocar o asterisco pelo nosso dominio real
const corsOptions = {
    origin: '*', // Exemplo de restricao: ['https://meudominio.com', 'http://localhost:3000']
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));


// ==========================================
// ROTAS DA APLICACAO
// ==========================================

// Rota principal solicitada na PBI
app.get('/', (req, res) => {
    res.status(200).send('Esteira DevSecOps Ativa!');
});

// Rota /health para monitoramento e health check
// PBI-22: Adicionado campo 'message' para validacao do teste dinamico (DAST/ZAP)
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'UP',
        message: 'Aplicacao disponivel para teste dinamico',
        timestamp: new Date().toISOString()
    });
});


// ==========================================
// TRATAMENTO DE ERROS (PBI-23)
// ==========================================

// Task 116: Revisar e restringir exposicao de erros genericos
// Se a aplicacao quebrar, ela nao vai "vazar" informacoes sensiveis do servidor para o atacante

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    // O erro real fica registrado apenas no terminal do servidor
    console.error('[ERRO INTERNO]:', err.message); 
    
    // O usuario recebe apenas uma mensagem generica de seguranca
    res.status(500).json({
        error: 'Internal Server Error',
        message: 'Algo deu errado no processamento da sua requisicao.'
    });
});

module.exports = app;