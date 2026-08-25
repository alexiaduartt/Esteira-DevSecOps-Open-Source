const express = require('express');
<<<<<<< HEAD
const app = express();

// Rota principal solicitada na PBI
=======
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

>>>>>>> 6798baf207ff17dba3dbdba2f8091821623e822b
app.get('/', (req, res) => {
    res.status(200).send('Esteira DevSecOps Ativa!');
});

<<<<<<< HEAD
// Rota /health para monitoramento e health check
=======
>>>>>>> 6798baf207ff17dba3dbdba2f8091821623e822b
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'UP',
        timestamp: new Date().toISOString()
    });
});

<<<<<<< HEAD
=======
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error('[ERRO INTERNO]:', err.message);

    res.status(500).json({
        error: 'Internal Server Error',
        message: 'Algo deu errado no processamento da sua requisicao.'
    });
});

>>>>>>> 6798baf207ff17dba3dbdba2f8091821623e822b
module.exports = app;