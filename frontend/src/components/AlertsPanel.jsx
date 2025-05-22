import React from 'react';
import { formatTimestamp, formatRelativeTime, getSeverityColor } from '../utils/formatters';

function AlertsPanel({ alerts, onAcknowledge, onResolve, compact }) {
  if (!alerts || alerts.length === 0) {
    return (
      <div className="empty-state">
        <p>No active alerts</p>
        <p className="text-sm text-muted">All systems operational</p>
      </div>
    );
  }

  const getSeverityBadge = (severity) => {
    const badgeClass = `badge-${severity}`;
    return <span className={`badge ${badgeClass}`}>{severity}</span>;
  };

  const getAlertIcon = (type) => {
    const icons = {
      errorBurst: '💥',
      frequencySpike: '📈',
      pattern: '🔍',
      mlBased: '🤖'
    };
    return icons[type] || '⚠️';
  };

  if (compact) {
    return (
      <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
        {alerts.slice(0, 5).map((alert) => (
          <div
            key={alert.id}
            className="log-entry"
            style={{
              borderLeftColor: getSeverityColor(alert.severity),
              marginBottom: '0.5rem',
              padding: '0.5rem 0.75rem'
            }}
          >
            <div className="flex flex-between flex-center">
              <div className="flex flex-center gap-2">
                <span>{getAlertIcon(alert.type)}</span>
                <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
              </div>
              <span className="text-xs text-muted">
                {formatRelativeTime(alert.createdAt)}
              </span>
            </div>
            <p className="text-sm mt-1">{alert.title}</p>
            <p className="text-xs text-muted mt-1">{alert.source}</p>
          </div>
        ))}
        {alerts.length > 5 && (
          <p className="text-xs text-muted text-center mt-2">
            +{alerts.length - 5} more alerts
          </p>
        )}
      </div>
    );
  }

  return (
    <div>
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Type</th>
              <th>Message</th>
              <th>Source</th>
              <th>Time</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td>{getSeverityBadge(alert.severity)}</td>
                <td>
                  <span className="flex flex-center gap-1">
                    {getAlertIcon(alert.type)}
                    <span className="text-sm">{alert.type}</span>
                  </span>
                </td>
                <td>
                  <div>
                    <p className="text-sm">{alert.title}</p>
                    <p className="text-xs text-muted">{alert.message?.substring(0, 50)}...</p>
                  </div>
                </td>
                <td>
                  <span className="text-sm">{alert.source || '-'}</span>
                </td>
                <td>
                  <span className="text-xs text-muted">{formatTimestamp(alert.createdAt)}</span>
                </td>
                <td>
                  <div className="flex gap-1">
                    {alert.status === 'active' && (
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => onAcknowledge?.(alert.id)}
                      >
                        Ack
                      </button>
                    )}
                    {alert.status !== 'resolved' && (
                      <button
                        className="btn btn-success btn-sm"
                        onClick={() => onResolve?.(alert.id)}
                      >
                        Resolve
                      </button>
                    )}
                    {alert.status === 'resolved' && (
                      <span className="badge badge-low">Resolved</span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AlertsPanel;
