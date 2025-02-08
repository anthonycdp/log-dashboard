const express = require('express');

const router = express.Router();

router.get('/detectors', (req, res) => {
  const { anomalyDetector } = req.stores;

  res.json({
    detectors: anomalyDetector.getDetectorInfo()
  });
});

router.get('/config', (req, res) => {
  const { anomalyDetector } = req.stores;

  res.json(anomalyDetector.getConfig());
});

router.put('/config', (req, res) => {
  const { anomalyDetector } = req.stores;

  anomalyDetector.updateConfig(req.body);
  res.json({
    message: 'Configuration updated',
    config: anomalyDetector.getConfig()
  });
});

router.post('/analyze', (req, res) => {
  const { anomalyDetector } = req.stores;

  const result = anomalyDetector.analyze(req.body);
  res.json(result || { detected: false });
});

router.get('/stats', (req, res) => {
  const { anomalyDetector } = req.stores;

  res.json(anomalyDetector.getStats());
});

module.exports = router;
