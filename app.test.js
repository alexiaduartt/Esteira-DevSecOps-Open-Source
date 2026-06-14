const request = require('supertest');
const app = require('./app'); // Isso puxa o seu app.js da imagem anterior

describe('Suite de Testes da PBI-07', () => {
    
    test('Task 1: Criar teste específico para rota /health', async () => {
        const response = await request(app).get('/health');
        
        // Validações baseadas no seu app.js
        expect(response.statusCode).toBe(200);
        expect(response.body.status).toBe('UP');
    });

});

// PBI-22: Testes de integração para validar a aplicação no contexto do teste dinâmico (DAST/ZAP)
describe('Suite de Testes da PBI-22 - Preparar aplicação para teste dinâmico', () => {

    test('GET /health deve retornar status HTTP 200', async () => {
        const response = await request(app).get('/health');
        expect(response.statusCode).toBe(200);
    });

    test('GET /health deve retornar status "UP"', async () => {
        const response = await request(app).get('/health');
        expect(response.body.status).toBe('UP');
    });

    test('GET /health deve conter o campo "message"', async () => {
        const response = await request(app).get('/health');
        expect(response.body).toHaveProperty('message');
        expect(typeof response.body.message).toBe('string');
        expect(response.body.message.length).toBeGreaterThan(0);
    });

    test('GET / deve retornar status HTTP 200', async () => {
        const response = await request(app).get('/');
        expect(response.statusCode).toBe(200);
    });

});
