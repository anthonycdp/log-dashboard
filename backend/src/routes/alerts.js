const express = require('express');
const { parseOptionalInt } = require('../utils/helpers');

const router = express.Router();

router.get('/', (req, res) => {
  const { alerts: alertStore } = req.stores;

  const options = {
    limit: parseOptionalInt(req.query.limit, 50),
    offset: parseOptionalInt(req.query.offset, 0),
    severity: req.query.severity,
    status: req.query.status,
    type: req.query.type,
    startTime: req.query.startTime,
    endTime: req.query.endTime,
    sortBy: req.query.sortBy || 'createdAt',
    sortOrder: req.query.sortOrder || 'desc'
  };

  res.json(alertStore.getAlerts(options));
});

router.get('/summary', (req, res) => {
  const { alerts: alertStore } = req.stores;

  res.json({
    active: alertStore.getActiveCount(),
    bySeverity: alertStore.getCountsBySeverity(),
    total: alertStore.alerts.length
  });
});

router.get('/:id', (req, res) => {
  const { alerts: alertStore } = req.stores;
  const alert = alertStore.getAlertById(req.params.id);

  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }

  res.json(alert);
});

router.post('/:id/acknowledge', (req, res) => {
  const { alerts: alertStore } = req.stores;
  const alert = alertStore.acknowledgeAlert(req.params.id);

  if (!alert) {
    return res.status(404).json({ error: 'Alert not found or already resolved' });
  }

  res.json(alert);
});

router.post('/:id/resolve', (req, res) => {
  const { alerts: alertStore } = req.stores;
  const alert = alertStore.resolveAlert(req.params.id);

  if (!alert) {
    return res.status(404).json({ error: 'Alert not found or already resolved' });
  }

  res.json(alert);
});

router.delete('/', (req, res) => {
  const { alerts: alertStore } = req.stores;
  alertStore.clear();
  res.json({ message: 'All alerts cleared' });
});

module.exports = router;
