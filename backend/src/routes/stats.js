const express = require('express');
const { TIME } = require('../config/constants');
const { parseOptionalInt } = require('../utils/helpers');

const router = express.Router();

router.get('/', (req, res) => {
  const { logs: logStore, alerts: alertStore } = req.stores;
  const timeWindow = parseOptionalInt(req.query.timeWindow, TIME.ONE_HOUR_MS);

  res.json(buildStatsResponse(logStore, alertStore, timeWindow));
});

router.get('/levels', (req, res) => {
  const { logs: logStore } = req.stores;
  const timeWindow = parseOptionalInt(req.query.timeWindow, TIME.ONE_HOUR_MS);

  res.json({
    counts: logStore.getLogsCountByLevel(timeWindow),
    timeSeries: logStore.getTimeSeriesData('minute', timeWindow),
    timeWindow,
    timestamp: new Date().toISOString()
  });
});

router.get('/services', (req, res) => {
  const { logs: logStore } = req.stores;
  const timeWindow = parseOptionalInt(req.query.timeWindow, TIME.ONE_HOUR_MS);

  res.json({
    counts: logStore.getLogsCountByService(timeWindow),
    timeWindow,
    timestamp: new Date().toISOString()
  });
});

function buildStatsResponse(logStore, alertStore, timeWindow) {
  return {
    logs: {
      total: logStore.getTotalCount(),
      byLevel: logStore.getLogsCountByLevel(timeWindow),
      byService: logStore.getLogsCountByService(timeWindow)
    },
    alerts: {
      active: alertStore.getActiveCount(),
      bySeverity: alertStore.getCountsBySeverity()
    },
    timeWindow,
    timestamp: new Date().toISOString()
  };
}

module.exports = router;
