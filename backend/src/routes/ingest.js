const express = require('express');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

router.post('/', (req, res) => {
  const { logs: logStore, anomalyDetector } = req.stores;
  const { logs } = req.body;

  if (!Array.isArray(logs)) {
    return res.status(400).json({ error: 'Logs must be an array' });
  }

  const processedLogs = logs.map(log => {
    const processedLog = logStore.addLog({
      ...log,
      id: uuidv4(),
      timestamp: log.timestamp || new Date().toISOString()
    });

    anomalyDetector.analyze(processedLog);
    return processedLog;
  });

  res.json({
    message: 'Logs ingested successfully',
    count: processedLogs.length
  });
});

module.exports = router;
