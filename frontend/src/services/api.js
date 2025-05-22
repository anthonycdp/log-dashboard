const API_BASE = '/api';

class ApiService {
  async fetchJson(url, options = {}) {
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(error.message || error.error?.message || 'Request failed');
    }

    return response.json();
  }

  buildSearchParams(params) {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (this.isValidParamValue(value)) {
        searchParams.append(key, value);
      }
    });
    return searchParams;
  }

  isValidParamValue(value) {
    return value !== undefined && value !== null && value !== '';
  }

  async getLogs(params = {}) {
    return this.fetchJson(`${API_BASE}/logs?${this.buildSearchParams(params)}`);
  }

  async getLogById(id) {
    return this.fetchJson(`${API_BASE}/logs/${id}`);
  }

  async getLogTimeline(id, window = 300000) {
    return this.fetchJson(`${API_BASE}/logs/${id}/timeline?window=${window}`);
  }

  async getTimeSeries(interval = 'minute', timeWindow = 3600000) {
    return this.fetchJson(`${API_BASE}/logs/timeseries?interval=${interval}&timeWindow=${timeWindow}`);
  }

  async createLog(log) {
    return this.fetchJson(`${API_BASE}/logs`, {
      method: 'POST',
      body: JSON.stringify(log)
    });
  }

  async ingestLogs(logs) {
    return this.fetchJson(`${API_BASE}/ingest`, {
      method: 'POST',
      body: JSON.stringify({ logs })
    });
  }

  async getAlerts(params = {}) {
    return this.fetchJson(`${API_BASE}/alerts?${this.buildSearchParams(params)}`);
  }

  async getAlertSummary() {
    return this.fetchJson(`${API_BASE}/alerts/summary`);
  }

  async acknowledgeAlert(id) {
    return this.fetchJson(`${API_BASE}/alerts/${id}/acknowledge`, { method: 'POST' });
  }

  async resolveAlert(id) {
    return this.fetchJson(`${API_BASE}/alerts/${id}/resolve`, { method: 'POST' });
  }

  async getStats(timeWindow = 3600000) {
    return this.fetchJson(`${API_BASE}/stats?timeWindow=${timeWindow}`);
  }

  async getLevelStats(timeWindow = 3600000) {
    return this.fetchJson(`${API_BASE}/stats/levels?timeWindow=${timeWindow}`);
  }

  async getServiceStats(timeWindow = 3600000) {
    return this.fetchJson(`${API_BASE}/stats/services?timeWindow=${timeWindow}`);
  }

  async getAnomalyDetectors() {
    return this.fetchJson(`${API_BASE}/anomaly/detectors`);
  }

  async getAnomalyConfig() {
    return this.fetchJson(`${API_BASE}/anomaly/config`);
  }

  async updateAnomalyConfig(config) {
    return this.fetchJson(`${API_BASE}/anomaly/config`, {
      method: 'PUT',
      body: JSON.stringify(config)
    });
  }

  async getAnomalyStats() {
    return this.fetchJson(`${API_BASE}/anomaly/stats`);
  }

  async startSimulation(interval = 2000, anomalyRate = 0.1) {
    return this.fetchJson(`${API_BASE}/simulation/start`, {
      method: 'POST',
      body: JSON.stringify({ interval, anomalyRate })
    });
  }

  async stopSimulation() {
    return this.fetchJson(`${API_BASE}/simulation/stop`, { method: 'POST' });
  }

  async getHealth() {
    return this.fetchJson('/health');
  }
}

export const api = new ApiService();
export default api;
