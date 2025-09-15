const request = require('supertest');
const app = require('../src/index');

describe('Log Dashboard API', () => {
  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body).toHaveProperty('timestamp');
      expect(res.body).toHaveProperty('stats');
    });
  });

  describe('Logs API', () => {
    it('should return empty logs initially', async () => {
      const res = await request(app).get('/api/logs');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('logs');
      expect(res.body).toHaveProperty('pagination');
    });

    it('should create a new log entry', async () => {
      const log = {
        level: 'info',
        message: 'Test log entry',
        service: 'test-service',
        source: 'test'
      };

      const res = await request(app)
        .post('/api/logs')
        .send(log);

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('id');
      expect(res.body.level).toBe('info');
      expect(res.body.message).toBe('Test log entry');
    });

    it('should filter logs by level', async () => {
      // Create some logs
      await request(app).post('/api/logs').send({ level: 'error', message: 'Error log' });
      await request(app).post('/api/logs').send({ level: 'info', message: 'Info log' });

      const res = await request(app).get('/api/logs?level=error');
      expect(res.status).toBe(200);
      expect(res.body.logs.every(log => log.level === 'error')).toBe(true);
    });

    it('should search logs by message', async () => {
      const uniqueMessage = `Unique test message ${Date.now()}`;
      await request(app).post('/api/logs').send({
        level: 'info',
        message: uniqueMessage
      });

      const res = await request(app).get(`/api/logs?search=${encodeURIComponent(uniqueMessage)}`);
      expect(res.status).toBe(200);
      expect(res.body.logs.length).toBeGreaterThan(0);
      expect(res.body.logs[0].message).toBe(uniqueMessage);
    });

    it('should return 404 for non-existent log', async () => {
      const res = await request(app).get('/api/logs/non-existent-id');
      expect(res.status).toBe(404);
    });
  });

  describe('Log Ingestion', () => {
    it('should ingest multiple logs', async () => {
      const logs = [
        { level: 'info', message: 'Log 1', service: 'svc1' },
        { level: 'error', message: 'Log 2', service: 'svc2' },
        { level: 'warn', message: 'Log 3', service: 'svc1' }
      ];

      const res = await request(app)
        .post('/api/ingest')
        .send({ logs });

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Logs ingested successfully');
      expect(res.body.count).toBe(3);
    });

    it('should reject non-array logs', async () => {
      const res = await request(app)
        .post('/api/ingest')
        .send({ logs: 'not an array' });

      expect(res.status).toBe(400);
    });
  });

  describe('Alerts API', () => {
    it('should return alerts list', async () => {
      const res = await request(app).get('/api/alerts');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('alerts');
      expect(res.body).toHaveProperty('pagination');
    });

    it('should return alert summary', async () => {
      const res = await request(app).get('/api/alerts/summary');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('active');
      expect(res.body).toHaveProperty('bySeverity');
    });
  });

  describe('Stats API', () => {
    it('should return statistics', async () => {
      const res = await request(app).get('/api/stats');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('logs');
      expect(res.body).toHaveProperty('alerts');
      expect(res.body.logs).toHaveProperty('total');
      expect(res.body.logs).toHaveProperty('byLevel');
    });

    it('should return level statistics', async () => {
      const res = await request(app).get('/api/stats/levels');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('counts');
      expect(res.body).toHaveProperty('timeSeries');
    });
  });

  describe('Anomaly Detection API', () => {
    it('should return available detectors', async () => {
      const res = await request(app).get('/api/anomaly/detectors');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('detectors');
      expect(res.body.detectors.length).toBeGreaterThan(0);
    });

    it('should return anomaly config', async () => {
      const res = await request(app).get('/api/anomaly/config');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('errorRateThreshold');
      expect(res.body).toHaveProperty('frequencyThreshold');
    });

    it('should update anomaly config', async () => {
      const res = await request(app)
        .put('/api/anomaly/config')
        .send({ errorRateThreshold: 0.5 });

      expect(res.status).toBe(200);
      expect(res.body.config.errorRateThreshold).toBe(0.5);
    });

    it('should return anomaly stats', async () => {
      const res = await request(app).get('/api/anomaly/stats');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('totalAnalyzed');
      expect(res.body).toHaveProperty('anomaliesDetected');
    });
  });

  describe('Simulation API', () => {
    it('should start simulation', async () => {
      const res = await request(app)
        .post('/api/simulation/start')
        .send({ interval: 5000, anomalyRate: 0.05 });

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Simulation started');
    });

    it('should stop simulation', async () => {
      // Start first
      await request(app).post('/api/simulation/start').send({});

      const res = await request(app).post('/api/simulation/stop');
      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Simulation stopped');
    });
  });
});
