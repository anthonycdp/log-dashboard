const express = require('express');
const cors = require('cors');

const logsRouter = require('./routes/logs');
const alertsRouter = require('./routes/alerts');
const statsRouter = require('./routes/stats');
const anomalyRouter = require('./routes/anomaly');
const ingestRouter = require('./routes/ingest');
const { errorHandler } = require('./middleware/errorHandler');
const { requestLogger } = require('./middleware/requestLogger');
const LogStore = require('./models/LogStore');
const AlertStore = require('./models/AlertStore');
const AnomalyDetector = require('./services/AnomalyDetector');
const LogSimulator = require('./services/LogSimulator');

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize stores
const logStore = new LogStore();
const alertStore = new AlertStore();
const anomalyDetector = new AnomalyDetector(logStore, alertStore);
const logSimulator = new LogSimulator(logStore, anomalyDetector);

// Make stores available to routes
app.locals.logStore = logStore;
app.locals.alertStore = alertStore;
app.locals.anomalyDetector = anomalyDetector;

// Middleware to attach stores to request
app.use((req, res, next) => {
  req.stores = {
    logs: logStore,
    alerts: alertStore,
    anomalyDetector: anomalyDetector
  };
  next();
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(requestLogger);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    stats: {
      totalLogs: logStore.getTotalCount(),
      activeAlerts: alertStore.getActiveCount()
    }
  });
});

// API Routes
app.use('/api/logs', logsRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/stats', statsRouter);
app.use('/api/anomaly', anomalyRouter);
app.use('/api/ingest', ingestRouter);

// Simulation endpoints
app.post('/api/simulation/start', (req, res) => {
  const { interval = 2000, anomalyRate = 0.1 } = req.body;
  logSimulator.start({ interval, anomalyRate });
  res.json({ message: 'Simulation started', interval, anomalyRate });
});

app.post('/api/simulation/stop', (req, res) => {
  logSimulator.stop();
  res.json({ message: 'Simulation stopped' });
});

// Error handling
app.use(errorHandler);

// Start server only if not in test mode
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`Log Dashboard API running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
  });
}

module.exports = app;
