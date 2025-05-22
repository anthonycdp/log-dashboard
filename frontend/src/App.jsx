import React, { useState, useCallback } from 'react';
import { usePolling } from './hooks/useApi';
import api from './services/api';
import Header from './components/Header';
import StatsCards from './components/StatsCards';
import LogsChart from './components/LogsChart';
import LogsTable from './components/LogsTable';
import AlertsPanel from './components/AlertsPanel';
import TimelineView from './components/TimelineView';
import SimulationControl from './components/SimulationControl';
import './styles/global.css';

const TABS = {
  DASHBOARD: 'dashboard',
  LOGS: 'logs',
  ALERTS: 'alerts',
  TIMELINE: 'timeline'
};

const POLLING_CONFIG = {
  STATS_INTERVAL_MS: 5000,
  ALERTS_INTERVAL_MS: 5000,
  TIMESERIES_INTERVAL_MS: 10000,
  STATS_TIME_WINDOW_MS: 3600000,
  ALERTS_LIMIT: 20
};

const EMPTY_FILTERS = {
  level: '',
  service: '',
  search: ''
};

function App() {
  const [activeTab, setActiveTab] = useState(TABS.DASHBOARD);
  const [selectedLog, setSelectedLog] = useState(null);
  const [filters, setFilters] = useState(EMPTY_FILTERS);

  const { data: stats, refresh: refreshStats } = usePolling(
    () => api.getStats(POLLING_CONFIG.STATS_TIME_WINDOW_MS),
    POLLING_CONFIG.STATS_INTERVAL_MS
  );

  const { data: alertsData, refresh: refreshAlerts } = usePolling(
    () => api.getAlerts({ status: 'active', limit: POLLING_CONFIG.ALERTS_LIMIT }),
    POLLING_CONFIG.ALERTS_INTERVAL_MS
  );

  const { data: timeSeries, refresh: refreshTimeSeries } = usePolling(
    () => api.getTimeSeries('minute', POLLING_CONFIG.STATS_TIME_WINDOW_MS),
    POLLING_CONFIG.TIMESERIES_INTERVAL_MS
  );

  const refreshAll = useCallback(() => {
    refreshStats();
    refreshAlerts();
    refreshTimeSeries();
  }, [refreshStats, refreshAlerts, refreshTimeSeries]);

  const handleLogSelect = (log) => {
    setSelectedLog(log);
    setActiveTab(TABS.TIMELINE);
  };

  return (
    <div className="app">
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        tabs={TABS}
        alertCount={alertsData?.alerts?.length || 0}
      />

      <main className="container" style={{ padding: '1.5rem 1rem' }}>
        {activeTab === TABS.DASHBOARD && (
          <>
            <SimulationControl onToggle={refreshAll} />

            <div className="grid grid-cols-4" style={{ marginBottom: '1.5rem' }}>
              <StatsCards stats={stats} />
            </div>

            <div className="grid grid-cols-2" style={{ marginBottom: '1.5rem' }}>
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title">Log Volume Over Time</h3>
                </div>
                <LogsChart data={timeSeries || []} />
              </div>

              <div className="card">
                <div className="card-header">
                  <h3 className="card-title">Active Alerts</h3>
                  <span className="badge badge-error">{alertsData?.pagination?.total || 0}</span>
                </div>
                <AlertsPanel
                  alerts={alertsData?.alerts || []}
                  onAcknowledge={async (id) => {
                    await api.acknowledgeAlert(id);
                    refreshAlerts();
                  }}
                  compact
                />
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Recent Logs</h3>
                <button className="btn btn-secondary btn-sm" onClick={() => setActiveTab(TABS.LOGS)}>
                  View All
                </button>
              </div>
              <LogsTable
                filters={filters}
                onFiltersChange={setFilters}
                limit={10}
                onLogSelect={handleLogSelect}
              />
            </div>
          </>
        )}

        {activeTab === TABS.LOGS && (
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Log Explorer</h3>
            </div>
            <LogsTable
              filters={filters}
              onFiltersChange={setFilters}
              onLogSelect={handleLogSelect}
            />
          </div>
        )}

        {activeTab === TABS.ALERTS && (
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Alert Management</h3>
            </div>
            <AlertsPanel
              alerts={alertsData?.alerts || []}
              onAcknowledge={async (id) => {
                await api.acknowledgeAlert(id);
                refreshAlerts();
              }}
              onResolve={async (id) => {
                await api.resolveAlert(id);
                refreshAlerts();
              }}
            />
          </div>
        )}

        {activeTab === TABS.TIMELINE && selectedLog && (
          <TimelineView
            logId={selectedLog.id}
            onBack={() => setActiveTab(TABS.LOGS)}
          />
        )}
      </main>
    </div>
  );
}

export default App;
