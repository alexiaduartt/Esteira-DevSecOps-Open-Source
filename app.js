const express = require('express');
const helmet = require('helmet'); // Importa o pacote de Headers de Segurança
const cors = require('cors');     // Importa o pacote de CORS
const app = express();

// ==========================================
// CONFIGURAÇÕES DE SEGURANÇA (PBI-23)
// ==========================================

// Task 114: Configurar headers básicos de segurança
// O Helmet esconde o "X-Powered-By" e adiciona proteções contra XSS, Clickjacking, etc.
app.use(helmet());

// Task 115: Revisar configurações de CORS
// Define quem pode acessar a API. Em produção, é so trocar o asterisco pelo nosso domínio real
const corsOptions = {
    origin: '*', // Exemplo de restrição: ['https://meudominio.com', 'http://localhost:3000']
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));


// ==========================================
//  ROTAS DA APLICAÇÃO
// ==========================================

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


// ==========================================
// TRATAMENTO DE ERROS (PBI-23)
// ==========================================

// Task 116: Revisar e restringir exposição de erros genéricos
// Se a aplicação quebrar, ela não vai "vazar" informações sensíveis do servidor para o atacante
app.use((err, req, res, next) => {
    // O erro real fica registrado apenas no terminal do servidor
    console.error('[ERRO INTERNO]:', err.message); 
    
    // O usuário recebe apenas uma mensagem genérica de segurança
    res.status(500).json({
        error: 'Internal Server Error',
        message: 'Algo deu errado no processamento da sua requisição.'
    });
});

module.exports = app;