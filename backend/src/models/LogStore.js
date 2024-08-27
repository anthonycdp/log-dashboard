const { TIME, LIMITS, PAGINATION } = require('../config/constants');

const VALID_LOG_LEVELS = ['error', 'warn', 'info', 'debug'];

class LogStore {
  constructor() {
    this.logs = [];
    this.maxLogs = LIMITS.MAX_LOGS;
  }

  addLog(log) {
    this.pruneIfNeeded();
    return this.createAndStoreLog(log);
  }

  pruneIfNeeded() {
    if (this.logs.length >= this.maxLogs) {
      const keepFromIndex = Math.floor(this.maxLogs * LIMITS.PRUNE_PERCENTAGE);
      this.logs = this.logs.slice(keepFromIndex);
    }
  }

  createAndStoreLog(log) {
    const enrichedLog = {
      ...log,
      id: log.id || this.generateId(),
      timestamp: log.timestamp || new Date().toISOString(),
      receivedAt: new Date().toISOString()
    };
    this.logs.push(enrichedLog);
    return enrichedLog;
  }

  generateId() {
    return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getLogs(options = {}) {
    const queryOptions = this.buildQueryOptions(options);
    let filtered = [...this.logs];

    filtered = this.applyFilters(filtered, queryOptions);
    filtered = this.applySorting(filtered, queryOptions);

    return this.paginateResults(filtered, queryOptions);
  }

  buildQueryOptions(options) {
    return {
      limit: options.limit ?? PAGINATION.DEFAULT_LIMIT,
      offset: options.offset ?? PAGINATION.DEFAULT_OFFSET,
      level: options.level,
      source: options.source,
      service: options.service,
      startTime: options.startTime,
      endTime: options.endTime,
      search: options.search,
      hasAnomaly: options.hasAnomaly,
      sortBy: options.sortBy || 'timestamp',
      sortOrder: options.sortOrder || 'desc'
    };
  }

  applyFilters(logs, options) {
    let filtered = logs;

    if (options.level) {
      const levels = this.normalizeToArray(options.level);
      filtered = filtered.filter(log => levels.includes(log.level));
    }

    if (options.source) {
      filtered = this.filterByCaseInsensitive(filtered, 'source', options.source);
    }

    if (options.service) {
      filtered = this.filterByCaseInsensitive(filtered, 'service', options.service);
    }

    if (options.startTime) {
      filtered = this.filterByTimeRange(filtered, options.startTime, null);
    }

    if (options.endTime) {
      filtered = this.filterByTimeRange(filtered, null, options.endTime);
    }

    if (options.search) {
      filtered = this.filterBySearch(filtered, options.search);
    }

    if (options.hasAnomaly !== undefined) {
      filtered = filtered.filter(log => log.hasAnomaly === options.hasAnomaly);
    }

    return filtered;
  }

  normalizeToArray(value) {
    return Array.isArray(value) ? value : [value];
  }

  filterByCaseInsensitive(logs, field, value) {
    const lowerValue = value.toLowerCase();
    return logs.filter(log =>
      log[field]?.toLowerCase().includes(lowerValue)
    );
  }

  filterByTimeRange(logs, startTime, endTime) {
    return logs.filter(log => {
      const logTime = new Date(log.timestamp);
      if (startTime && logTime < new Date(startTime)) return false;
      if (endTime && logTime > new Date(endTime)) return false;
      return true;
    });
  }

  filterBySearch(logs, searchTerm) {
    const searchLower = searchTerm.toLowerCase();
    return logs.filter(log =>
      log.message?.toLowerCase().includes(searchLower) ||
      log.source?.toLowerCase().includes(searchLower) ||
      log.service?.toLowerCase().includes(searchLower) ||
      this.searchInMetadata(log.metadata, searchLower)
    );
  }

  searchInMetadata(metadata, searchTerm) {
    if (!metadata) return false;
    return JSON.stringify(metadata).toLowerCase().includes(searchTerm);
  }

  applySorting(logs, options) {
    const { sortBy, sortOrder } = options;
    return logs.sort((a, b) => {
      const comparison = a[sortBy] > b[sortBy] ? 1 : -1;
      return sortOrder === 'desc' ? -comparison : comparison;
    });
  }

  paginateResults(logs, options) {
    const { limit, offset } = options;
    const total = logs.length;
    const paginatedLogs = logs.slice(offset, offset + limit);

    return {
      logs: paginatedLogs,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total
      }
    };
  }

  getLogById(id) {
    return this.logs.find(log => log.id === id);
  }

  getLogsByTimeRange(startTime, endTime) {
    return this.filterByTimeRange(this.logs, startTime, endTime);
  }

  getLogsCountByLevel(timeWindow = TIME.ONE_HOUR_MS) {
    const cutoff = Date.now() - timeWindow;
    const counts = this.createEmptyLevelCounts();

    this.logs.forEach(log => {
      if (this.isLogInTimeWindow(log, cutoff) && this.isValidLevel(log.level)) {
        counts[log.level]++;
      }
    });

    return counts;
  }

  createEmptyLevelCounts() {
    return { error: 0, warn: 0, info: 0, debug: 0 };
  }

  isValidLevel(level) {
    return VALID_LOG_LEVELS.includes(level);
  }

  isLogInTimeWindow(log, cutoffTime) {
    return new Date(log.timestamp).getTime() >= cutoffTime;
  }

  getLogsCountByService(timeWindow = TIME.ONE_HOUR_MS) {
    const cutoff = Date.now() - timeWindow;
    const counts = {};

    this.logs.forEach(log => {
      if (this.isLogInTimeWindow(log, cutoff) && log.service) {
        counts[log.service] = (counts[log.service] || 0) + 1;
      }
    });

    return counts;
  }

  getTotalCount() {
    return this.logs.length;
  }

  clear() {
    this.logs = [];
  }

  getTimeSeriesData(interval = 'minute', timeWindow = TIME.ONE_HOUR_MS) {
    const cutoff = Date.now() - timeWindow;
    const buckets = {};

    this.logs.forEach(log => {
      if (this.isLogInTimeWindow(log, cutoff)) {
        this.addToBucket(buckets, log, interval);
      }
    });

    return Object.entries(buckets)
      .map(([timestamp, counts]) => ({ timestamp, ...counts }))
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  }

  addToBucket(buckets, log, interval) {
    const bucketKey = this.getBucketKey(new Date(log.timestamp).getTime(), interval);
    if (!buckets[bucketKey]) {
      buckets[bucketKey] = this.createEmptyLevelCounts();
      buckets[bucketKey].total = 0;
    }
    if (this.isValidLevel(log.level)) {
      buckets[bucketKey][log.level]++;
    }
    buckets[bucketKey].total++;
  }

  getBucketKey(timestamp, interval) {
    const date = new Date(timestamp);
    const isoString = date.toISOString();

    switch (interval) {
      case 'hour':
        return isoString.slice(0, 13) + ':00:00';
      case 'minute':
      default:
        return isoString.slice(0, 16) + ':00';
    }
  }
}

module.exports = LogStore;
