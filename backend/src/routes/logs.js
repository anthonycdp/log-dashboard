const express = require('express');
const { TIME } = require('../config/constants');
const { parseBooleanParam, parseOptionalInt } = require('../utils/helpers');

const router = express.Router();

router.get('/', (req, res) => {
  const { logs: logStore } = req.stores;

  const options = {
    limit: parseOptionalInt(req.query.limit, 100),
    offset: parseOptionalInt(req.query.offset, 0),
    level: req.query.level,
    source: req.query.source,
    service: req.query.service,
    startTime: req.query.startTime,
    endTime: req.query.endTime,
    search: req.query.search,
    hasAnomaly: parseBooleanParam(req.query.hasAnomaly),
    sortBy: req.query.sortBy || 'timestamp',
    sortOrder: req.query.sortOrder || 'desc'
  };

  res.json(logStore.getLogs(options));
});

router.get('/timeseries', (req, res) => {
  const { logs: logStore } = req.stores;
  const interval = req.query.interval || 'minute';
  const timeWindow = parseOptionalInt(req.query.timeWindow, TIME.ONE_HOUR_MS);

  res.json(logStore.getTimeSeriesData(interval, timeWindow));
});

router.get('/:id', (req, res) => {
  const { logs: logStore } = req.stores;
  const log = logStore.getLogById(req.params.id);

  if (!log) {
    return res.status(404).json({ error: 'Log not found' });
  }

  res.json(log);
});

router.get('/:id/timeline', (req, res) => {
  const { logs: logStore } = req.stores;
  const log = logStore.getLogById(req.params.id);

  if (!log) {
    return res.status(404).json({ error: 'Log not found' });
  }

  const timelineData = buildTimelineData(logStore, log, req.query.window);
  res.json(timelineData);
});

function buildTimelineData(logStore, centerLog, windowMs) {
  const logTime = new Date(centerLog.timestamp).getTime();
  const window = parseOptionalInt(windowMs, TIME.FIVE_MINUTES_MS);

  const relatedLogs = logStore.getLogsByTimeRange(
    new Date(logTime - window).toISOString(),
    new Date(logTime + window).toISOString()
  ).filter(l => l.id !== centerLog.id);

  return {
    centerLog,
    relatedLogs: relatedLogs.sort((a, b) =>
      new Date(a.timestamp) - new Date(b.timestamp)
    ),
    windowMs: window
  };
}

router.post('/', (req, res) => {
  const { logs: logStore, anomalyDetector } = req.stores;

  const log = logStore.addLog(req.body);
  const anomalyResult = anomalyDetector.analyze(log);

  if (anomalyResult) {
    log.hasAnomaly = true;
    log.anomalyScore = anomalyResult.score;
    log.anomalyType = anomalyResult.type;
  }

  res.status(201).json(log);
});

router.delete('/', (req, res) => {
  const { logs: logStore } = req.stores;
  logStore.clear();
  res.json({ message: 'All logs cleared' });
});

module.exports = router;
