const LogStore = require('../src/models/LogStore');
const AlertStore = require('../src/models/AlertStore');

describe('LogStore', () => {
  let store;

  beforeEach(() => {
    store = new LogStore();
  });

  describe('addLog', () => {
    it('should add a log with generated id', () => {
      const log = store.addLog({ level: 'info', message: 'Test' });

      expect(log).toHaveProperty('id');
      expect(log).toHaveProperty('timestamp');
      expect(log).toHaveProperty('receivedAt');
      expect(log.level).toBe('info');
    });

    it('should use provided id and timestamp', () => {
      const log = store.addLog({
        id: 'custom-id',
        level: 'info',
        message: 'Test',
        timestamp: '2024-01-01T00:00:00.000Z'
      });

      expect(log.id).toBe('custom-id');
      expect(log.timestamp).toBe('2024-01-01T00:00:00.000Z');
    });
  });

  describe('getLogs', () => {
    beforeEach(() => {
      store.addLog({ level: 'error', message: 'Error 1', service: 'api' });
      store.addLog({ level: 'info', message: 'Info 1', service: 'web' });
      store.addLog({ level: 'warn', message: 'Warning 1', service: 'api' });
      store.addLog({ level: 'error', message: 'Error 2', service: 'db' });
    });

    it('should return paginated logs', () => {
      const result = store.getLogs({ limit: 2 });

      expect(result.logs.length).toBe(2);
      expect(result.pagination.total).toBe(4);
      expect(result.pagination.hasMore).toBe(true);
    });

    it('should filter by level', () => {
      const result = store.getLogs({ level: 'error' });

      expect(result.logs.length).toBe(2);
      expect(result.logs.every(l => l.level === 'error')).toBe(true);
    });

    it('should filter by service', () => {
      const result = store.getLogs({ service: 'api' });

      expect(result.logs.length).toBe(2);
      expect(result.logs.every(l => l.service === 'api')).toBe(true);
    });

    it('should search by message', () => {
      const result = store.getLogs({ search: 'Error' });

      expect(result.logs.length).toBe(2);
    });

    it('should sort by timestamp descending by default', () => {
      const result = store.getLogs({});

      expect(result.logs[0].timestamp >= result.logs[1].timestamp).toBe(true);
    });

    it('should sort ascending when specified', () => {
      const result = store.getLogs({ sortOrder: 'asc' });

      expect(result.logs[0].timestamp <= result.logs[1].timestamp).toBe(true);
    });
  });

  describe('getLogById', () => {
    it('should return log by id', () => {
      const added = store.addLog({ level: 'info', message: 'Test' });
      const found = store.getLogById(added.id);

      expect(found).toEqual(added);
    });

    it('should return undefined for non-existent id', () => {
      const found = store.getLogById('non-existent');

      expect(found).toBeUndefined();
    });
  });

  describe('getLogsCountByLevel', () => {
    it('should count logs by level', () => {
      store.addLog({ level: 'error', message: 'E1' });
      store.addLog({ level: 'error', message: 'E2' });
      store.addLog({ level: 'info', message: 'I1' });
      store.addLog({ level: 'warn', message: 'W1' });

      const counts = store.getLogsCountByLevel();

      expect(counts.error).toBe(2);
      expect(counts.info).toBe(1);
      expect(counts.warn).toBe(1);
    });
  });

  describe('getTimeSeriesData', () => {
    it('should return time series buckets', () => {
      const now = Date.now();
      store.addLog({ level: 'error', message: 'E1', timestamp: new Date(now).toISOString() });
      store.addLog({ level: 'info', message: 'I1', timestamp: new Date(now).toISOString() });

      const data = store.getTimeSeriesData('minute', 60000);

      expect(Array.isArray(data)).toBe(true);
      expect(data.length).toBeGreaterThan(0);
      expect(data[0]).toHaveProperty('timestamp');
      expect(data[0]).toHaveProperty('error');
      expect(data[0]).toHaveProperty('info');
    });
  });

  describe('maxLogs limit', () => {
    it('should remove old logs when limit exceeded', () => {
      const smallStore = new LogStore();
      smallStore.maxLogs = 10;

      for (let i = 0; i < 15; i++) {
        smallStore.addLog({ level: 'info', message: `Log ${i}` });
      }

      expect(smallStore.logs.length).toBeLessThan(15);
    });
  });
});

describe('AlertStore', () => {
  let store;

  beforeEach(() => {
    store = new AlertStore();
  });

  describe('addAlert', () => {
    it('should add an alert with generated id', () => {
      const alert = store.addAlert({
        type: 'errorBurst',
        severity: 'high',
        title: 'Test Alert'
      });

      expect(alert).toHaveProperty('id');
      expect(alert).toHaveProperty('createdAt');
      expect(alert.status).toBe('active');
    });
  });

  describe('getAlerts', () => {
    beforeEach(() => {
      store.addAlert({ type: 'errorBurst', severity: 'critical', title: 'Alert 1' });
      store.addAlert({ type: 'frequencySpike', severity: 'high', title: 'Alert 2' });
    });

    it('should filter by severity', () => {
      const result = store.getAlerts({ severity: 'critical' });

      expect(result.alerts.length).toBe(1);
      expect(result.alerts[0].severity).toBe('critical');
    });

    it('should filter by status', () => {
      store.alerts[0].status = 'resolved';

      const result = store.getAlerts({ status: 'active' });

      expect(result.alerts.length).toBe(1);
      expect(result.alerts[0].status).toBe('active');
    });
  });

  describe('acknowledgeAlert', () => {
    it('should acknowledge an active alert', () => {
      const alert = store.addAlert({ type: 'test', severity: 'high', title: 'Test' });
      const updated = store.acknowledgeAlert(alert.id);

      expect(updated.status).toBe('acknowledged');
      expect(updated).toHaveProperty('acknowledgedAt');
    });

    it('should return null for resolved alert', () => {
      const alert = store.addAlert({ type: 'test', severity: 'high', title: 'Test' });
      store.resolveAlert(alert.id);

      const result = store.acknowledgeAlert(alert.id);

      expect(result).toBeNull();
    });
  });

  describe('resolveAlert', () => {
    it('should resolve an alert', () => {
      const alert = store.addAlert({ type: 'test', severity: 'high', title: 'Test' });
      const updated = store.resolveAlert(alert.id);

      expect(updated.status).toBe('resolved');
      expect(updated).toHaveProperty('resolvedAt');
    });
  });

  describe('getCountsBySeverity', () => {
    it('should count active alerts by severity', () => {
      store.addAlert({ type: 't1', severity: 'critical', title: 'A1' });
      store.addAlert({ type: 't2', severity: 'critical', title: 'A2' });
      store.addAlert({ type: 't3', severity: 'high', title: 'A3' });

      const counts = store.getCountsBySeverity();

      expect(counts.critical).toBe(2);
      expect(counts.high).toBe(1);
    });

    it('should only count active alerts', () => {
      const alert = store.addAlert({ type: 't1', severity: 'critical', title: 'A1' });
      store.resolveAlert(alert.id);

      const counts = store.getCountsBySeverity();

      expect(counts.critical).toBe(0);
    });
  });
});
