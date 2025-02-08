/**
 * Middleware to inject stores into request context
 * Eliminates repetitive req.app.locals access throughout routes
 */

function injectStores(req, res, next) {
  req.stores = {
    logs: req.app.locals.logStore,
    alerts: req.app.locals.alertStore,
    anomalyDetector: req.app.locals.anomalyDetector
  };
  next();
}

module.exports = { injectStores };
