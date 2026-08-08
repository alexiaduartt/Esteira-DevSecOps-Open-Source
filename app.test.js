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

// =============================================================================
// Testes de Segurança — Validação de headers e comportamento seguro
// =============================================================================
describe('Testes de Segurança — Headers e configurações (Helmet)', () => {

    test('não deve expor o header X-Powered-By', async () => {
        const response = await request(app).get('/');
        expect(response.headers['x-powered-by']).toBeUndefined();
    });

    test('deve incluir header X-Content-Type-Options: nosniff', async () => {
        const response = await request(app).get('/');
        expect(response.headers['x-content-type-options']).toBe('nosniff');
    });

    test('deve incluir header X-Frame-Options para proteção contra Clickjacking', async () => {
        const response = await request(app).get('/');
        // Helmet define SAMEORIGIN por padrão
        expect(response.headers['x-frame-options']).toBeDefined();
    });

    test('deve incluir header Strict-Transport-Security', async () => {
        const response = await request(app).get('/');
        expect(response.headers['strict-transport-security']).toBeDefined();
    });

    test('deve incluir header Content-Security-Policy', async () => {
        const response = await request(app).get('/');
        expect(response.headers['content-security-policy']).toBeDefined();
    });

});

describe('Testes de Segurança — Tratamento de erros', () => {

    test('rotas inexistentes devem retornar 404, não 500', async () => {
        const response = await request(app).get('/rota-que-nao-existe');
        // Express retorna 404 por padrão para rotas não definidas
        expect(response.statusCode).toBe(404);
    });

    test('respostas de erro não devem conter stack trace', async () => {
        const response = await request(app).get('/rota-que-nao-existe');
        expect(response.body.stack).toBeUndefined();
        expect(response.text).not.toContain('at Function');
        expect(response.text).not.toContain('node_modules');
    });

});

describe('Testes de Segurança — CORS', () => {

    test('deve incluir headers de CORS na resposta', async () => {
        const response = await request(app)
            .get('/')
            .set('Origin', 'http://example.com');
        expect(response.headers['access-control-allow-origin']).toBeDefined();
    });

    test('deve aceitar apenas métodos HTTP permitidos', async () => {
        const response = await request(app)
            .options('/')
            .set('Origin', 'http://example.com')
            .set('Access-Control-Request-Method', 'GET');
        expect(response.statusCode).toBeLessThan(400);
    });

});

describe('Testes Funcionais — Conteúdo das respostas', () => {

    test('GET /health deve conter campo timestamp em formato ISO', async () => {
        const response = await request(app).get('/health');
        expect(response.body).toHaveProperty('timestamp');
        // Valida que é um ISO 8601 válido
        const date = new Date(response.body.timestamp);
        expect(date.toISOString()).toBe(response.body.timestamp);
    });

    test('GET / deve retornar o texto esperado da esteira', async () => {
        const response = await request(app).get('/');
        expect(response.text).toContain('Esteira DevSecOps Ativa');
    });

    test('GET /health deve retornar Content-Type application/json', async () => {
        const response = await request(app).get('/health');
        expect(response.headers['content-type']).toMatch(/application\/json/);
    });

});
