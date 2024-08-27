const { LIMITS, PAGINATION } = require('../config/constants');

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];

class AlertStore {
  constructor() {
    this.alerts = [];
    this.maxAlerts = LIMITS.MAX_ALERTS;
  }

  addAlert(alert) {
    this.pruneIfNeeded();
    return this.createAndStoreAlert(alert);
  }

  pruneIfNeeded() {
    if (this.alerts.length >= this.maxAlerts) {
      const keepFromIndex = Math.floor(this.maxAlerts * LIMITS.PRUNE_PERCENTAGE);
      this.alerts = this.alerts.slice(keepFromIndex);
    }
  }

  createAndStoreAlert(alert) {
    const enrichedAlert = {
      ...alert,
      id: alert.id || this.generateId(),
      createdAt: new Date().toISOString(),
      status: 'active',
      acknowledgedAt: null,
      resolvedAt: null
    };
    this.alerts.push(enrichedAlert);
    return enrichedAlert;
  }

  generateId() {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getAlerts(options = {}) {
    const queryOptions = this.buildQueryOptions(options);
    let filtered = [...this.alerts];

    filtered = this.applyFilters(filtered, queryOptions);
    filtered = this.applySorting(filtered, queryOptions);

    return this.paginateResults(filtered, queryOptions);
  }

  buildQueryOptions(options) {
    return {
      limit: options.limit ?? PAGINATION.DEFAULT_ALERTS_LIMIT,
      offset: options.offset ?? PAGINATION.DEFAULT_OFFSET,
      severity: options.severity,
      status: options.status,
      type: options.type,
      startTime: options.startTime,
      endTime: options.endTime,
      sortBy: options.sortBy || 'createdAt',
      sortOrder: options.sortOrder || 'desc'
    };
  }

  applyFilters(alerts, options) {
    let filtered = alerts;

    if (options.severity) {
      const severities = this.normalizeToArray(options.severity);
      filtered = filtered.filter(alert => severities.includes(alert.severity));
    }

    if (options.status) {
      const statuses = this.normalizeToArray(options.status);
      filtered = filtered.filter(alert => statuses.includes(alert.status));
    }

    if (options.type) {
      filtered = filtered.filter(alert => alert.type === options.type);
    }

    if (options.startTime) {
      const start = new Date(options.startTime);
      filtered = filtered.filter(alert => new Date(alert.createdAt) >= start);
    }

    if (options.endTime) {
      const end = new Date(options.endTime);
      filtered = filtered.filter(alert => new Date(alert.createdAt) <= end);
    }

    return filtered;
  }

  normalizeToArray(value) {
    return Array.isArray(value) ? value : [value];
  }

  applySorting(alerts, options) {
    const { sortBy, sortOrder } = options;
    return alerts.sort((a, b) => {
      const comparison = a[sortBy] > b[sortBy] ? 1 : -1;
      return sortOrder === 'desc' ? -comparison : comparison;
    });
  }

  paginateResults(alerts, options) {
    const { limit, offset } = options;
    const total = alerts.length;
    const paginatedAlerts = alerts.slice(offset, offset + limit);

    return {
      alerts: paginatedAlerts,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total
      }
    };
  }

  getAlertById(id) {
    return this.alerts.find(alert => alert.id === id);
  }

  acknowledgeAlert(id) {
    const alert = this.findActiveAlert(id);
    if (!alert) return null;

    alert.status = 'acknowledged';
    alert.acknowledgedAt = new Date().toISOString();
    return alert;
  }

  resolveAlert(id) {
    const alert = this.findUnresolvedAlert(id);
    if (!alert) return null;

    alert.status = 'resolved';
    alert.resolvedAt = new Date().toISOString();
    return alert;
  }

  findActiveAlert(id) {
    const alert = this.alerts.find(a => a.id === id);
    return alert?.status === 'active' ? alert : null;
  }

  findUnresolvedAlert(id) {
    const alert = this.alerts.find(a => a.id === id);
    return alert?.status !== 'resolved' ? alert : null;
  }

  getActiveCount() {
    return this.alerts.filter(a => a.status === 'active').length;
  }

  getCountsBySeverity() {
    const counts = this.createEmptySeverityCounts();

    this.alerts.forEach(alert => {
      if (alert.status === 'active' && this.isValidSeverity(alert.severity)) {
        counts[alert.severity]++;
      }
    });

    return counts;
  }

  createEmptySeverityCounts() {
    return { critical: 0, high: 0, medium: 0, low: 0 };
  }

  isValidSeverity(severity) {
    return VALID_SEVERITIES.includes(severity);
  }

  clear() {
    this.alerts = [];
  }
}

module.exports = AlertStore;
