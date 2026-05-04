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