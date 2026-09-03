const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

const DEFAULT_ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://127.0.0.1:3000'
];

const parseAllowedOrigins = () => {
    const configuredOrigins = process.env.ALLOWED_ORIGINS;

    if (!configuredOrigins) {
        return DEFAULT_ALLOWED_ORIGINS;
    }

    return configuredOrigins
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean);
};

const allowedOrigins = parseAllowedOrigins();

const corsOptions = {
    origin(origin, callback) {
        if (!origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
    optionsSuccessStatus: 204,
    maxAge: 600
};

app.use(helmet());
app.use(cors(corsOptions));

app.get('/', (req, res) => {
    res.status(200).send('Esteira DevSecOps Ativa!');
});

app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'UP',
        timestamp: new Date().toISOString(),
        message: 'Serviço em operação'
    });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error('[ERRO INTERNO]:', err.message);

    res.status(500).json({
        error: 'Internal Server Error',
        message: 'Algo deu errado no processamento da sua requisicao.'
    });
});

//linha teste para blabalbalbalbla

module.exports = app;