/**
 * Log Simulator Service
 * Generates realistic log data for testing and demonstration
 */

const LevelProbability = {
  ERROR: 0.05,
  WARN: 0.15,
  INFO: 0.5
};

const CRITICAL_THRESHOLD = 0.3;
const CRITICAL_SERVICE_COUNT = 3;
const BATCH_TIME_SPREAD_MS = 2000;

class LogSimulator {
  constructor(logStore, anomalyDetector) {
    this.logStore = logStore;
    this.anomalyDetector = anomalyDetector;
    this.interval = null;
    this.config = {
      interval: 2000,
      anomalyRate: 0.1
    };

    this.services = [
      'api-gateway',
      'auth-service',
      'user-service',
      'order-service',
      'payment-service',
      'notification-service',
      'analytics-service'
    ];

    this.sources = ['app', 'system', 'database', 'cache', 'queue', 'external'];

    this.normalMessages = {
      info: [
        'Request processed successfully',
        'User logged in',
        'Cache hit for key',
        'Database query executed',
        'API response sent',
        'Health check passed',
        'Configuration loaded',
        'Connection established'
      ],
      debug: [
        'Processing request payload',
        'Validating input parameters',
        'Cache lookup initiated',
        'Query plan generated',
        'Response serialization started'
      ],
      warn: [
        'Slow query detected',
        'Cache miss',
        'Retry attempt',
        'Rate limit approaching',
        'Memory usage high',
        'Connection pool near limit'
      ],
      error: [
        'Database connection failed',
        'Authentication failed',
        'Request timeout',
        'Service unavailable',
        'Invalid input received',
        'Internal server error'
      ]
    };

    this.anomalyMessages = {
      critical: [
        'CRITICAL: System failure detected',
        'CRITICAL: Data corruption suspected',
        'CRITICAL: Security breach attempt',
        'CRITICAL: Service cascade failure'
      ],
      error: [
        'ERROR: Unexpected exception in core module',
        'ERROR: Memory allocation failed',
        'ERROR: Out of memory exception',
        'ERROR: Stack overflow detected',
        'ERROR: Null pointer exception in payment processing'
      ]
    };
  }

  start(options = {}) {
    if (this.interval) {
      this.stop();
    }

    this.config = { ...this.config, ...options };

    this.interval = setInterval(() => {
      this.generateLog();
    }, this.config.interval);

    console.log(`Log simulator started (interval: ${this.config.interval}ms, anomaly rate: ${(this.config.anomalyRate * 100).toFixed(0)}%)`);
  }

  stop() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
      console.log('Log simulator stopped');
    }
  }

  isRunning() {
    return this.interval !== null;
  }

  generateLog() {
    const isAnomaly = Math.random() < this.config.anomalyRate;
    const log = isAnomaly ? this.generateAnomalyLog() : this.generateNormalLog();

    const addedLog = this.logStore.addLog(log);
    this.anomalyDetector.analyze(addedLog);

    return addedLog;
  }

  generateNormalLog() {
    const level = this.getRandomLevel();
    const service = this.randomChoice(this.services);
    const source = this.randomChoice(this.sources);
    const messages = this.normalMessages[level] || this.normalMessages.info;

    return {
      level,
      message: this.randomChoice(messages),
      service,
      source,
      timestamp: new Date().toISOString(),
      metadata: this.generateMetadata(level, service),
      hasAnomaly: false
    };
  }

  generateAnomalyLog() {
    const severity = Math.random() < CRITICAL_THRESHOLD ? 'critical' : 'error';
    const messages = this.anomalyMessages[severity];
    const criticalServices = this.services.slice(0, CRITICAL_SERVICE_COUNT);
    const service = this.randomChoice(criticalServices);
    const source = this.randomChoice(['app', 'database', 'external']);

    return {
      level: 'error',
      message: this.randomChoice(messages),
      service,
      source,
      timestamp: new Date().toISOString(),
      metadata: {
        ...this.generateMetadata('error', service),
        anomalyInduced: true,
        severity
      },
      hasAnomaly: false
    };
  }

  getRandomLevel() {
    const rand = Math.random();
    if (rand < LevelProbability.ERROR) return 'error';
    if (rand < LevelProbability.WARN) return 'warn';
    if (rand < LevelProbability.INFO) return 'info';
    return 'debug';
  }

  generateMetadata(level, service) {
    const metadata = {
      requestId: this.generateRequestId(),
      duration: Math.floor(Math.random() * 500) + 1
    };

    if (level === 'error') {
      metadata.errorCode = `ERR_${Math.floor(Math.random() * 9000) + 1000}`;
      metadata.stackTrace = this.generateStackTrace();
    }

    if (service === 'api-gateway') {
      metadata.endpoint = this.randomChoice(['/api/users', '/api/orders', '/api/products', '/api/auth']);
      metadata.method = this.randomChoice(['GET', 'POST', 'PUT', 'DELETE']);
    }

    return metadata;
  }

  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateStackTrace() {
    const frames = [
      'at UserService.findById (user.service.js:45)',
      'at AuthMiddleware.verify (auth.middleware.js:23)',
      'at RequestHandler.handle (handler.js:112)',
      'at processTicksAndRejections (node:internal/process/task_queues:95)'
    ];
    return frames.slice(0, Math.floor(Math.random() * 3) + 1).join('\n');
  }

  randomChoice(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  generateBatch(count = 100, anomalyRate = 0.1) {
    const logs = [];
    const baseTime = Date.now() - (count * BATCH_TIME_SPREAD_MS);

    for (let i = 0; i < count; i++) {
      const isAnomaly = Math.random() < anomalyRate;
      const log = isAnomaly ? this.generateAnomalyLog() : this.generateNormalLog();
      log.timestamp = new Date(baseTime + (i * BATCH_TIME_SPREAD_MS)).toISOString();
      logs.push(log);
    }

    return logs;
  }
}

module.exports = LogSimulator;
