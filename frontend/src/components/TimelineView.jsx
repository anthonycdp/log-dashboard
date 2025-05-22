import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { formatTimestamp } from '../utils/formatters';

function TimelineView({ logId, onBack }) {
  const [timeline, setTimeline] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [windowSize, setWindowSize] = useState(300000); // 5 minutes

  useEffect(() => {
    const fetchTimeline = async () => {
      setLoading(true);
      try {
        const data = await api.getLogTimeline(logId, windowSize);
        setTimeline(data);
        setError(null);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    if (logId) {
      fetchTimeline();
    }
  }, [logId, windowSize]);

  if (loading) {
    return (
      <div className="card">
        <div className="loading">
          <div className="spinner" />
          <span className="ml-2">Loading timeline...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <div className="empty-state">
          <p>Error loading timeline: {error}</p>
          <button className="btn btn-secondary mt-2" onClick={onBack}>
            Go Back
          </button>
        </div>
      </div>
    );
  }

  if (!timeline) return null;

  const { centerLog, relatedLogs } = timeline;

  // Sort all logs by timestamp
  const allLogs = [centerLog, ...relatedLogs].sort(
    (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
  );

  return (
    <div className="card">
      <div className="card-header">
        <div className="flex flex-center gap-4">
          <button className="btn btn-secondary btn-sm" onClick={onBack}>
            ← Back to Logs
          </button>
          <h3 className="card-title">Incident Timeline</h3>
        </div>
        <div className="flex flex-center gap-2">
          <span className="text-sm text-muted">Window:</span>
          <select
            value={windowSize}
            onChange={(e) => setWindowSize(Number(e.target.value))}
            className="btn btn-secondary btn-sm"
          >
            <option value={60000}>1 minute</option>
            <option value={300000}>5 minutes</option>
            <option value={600000}>10 minutes</option>
            <option value={1800000}>30 minutes</option>
          </select>
        </div>
      </div>

      <div style={{ padding: '1rem 0' }}>
        {/* Center Log Info */}
        <div
          className="card"
          style={{
            marginBottom: '1.5rem',
            borderLeft: '4px solid var(--accent-red)',
            background: 'rgba(239, 68, 68, 0.1)'
          }}
        >
          <div className="flex flex-between flex-center mb-2">
            <div className="flex flex-center gap-2">
              <span className={`badge badge-${centerLog.level}`}>{centerLog.level}</span>
              {centerLog.hasAnomaly && (
                <span className="badge badge-critical">ANOMALY DETECTED</span>
              )}
            </div>
            <span className="text-sm mono">{formatTimestamp(centerLog.timestamp)}</span>
          </div>
          <p style={{ marginBottom: '0.5rem' }}>{centerLog.message}</p>
          <div className="flex gap-4 text-sm text-muted">
            <span>Service: {centerLog.service}</span>
            <span>Source: {centerLog.source}</span>
            <span>ID: {centerLog.id}</span>
          </div>
          {centerLog.anomalyScore && (
            <div className="mt-2 p-2" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '4px' }}>
              <p className="text-sm">
                <strong>Anomaly Score:</strong> {centerLog.anomalyScore.toFixed(3)}
              </p>
              <p className="text-sm">
                <strong>Type:</strong> {centerLog.anomalyType}
              </p>
            </div>
          )}
        </div>

        {/* Timeline */}
        <h4 className="text-sm text-muted mb-4">
          Related Events ({relatedLogs.length} logs within {windowSize / 60000} min window)
        </h4>

        <div className="timeline">
          {allLogs.map((log, index) => {
            const isCenter = log.id === centerLog.id;
            return (
              <div
                key={log.id}
                className={`timeline-item ${isCenter ? 'center' : ''}`}
              >
                <div
                  className="card"
                  style={{
                    padding: '0.75rem',
                    background: isCenter ? 'rgba(239, 68, 68, 0.1)' : 'var(--bg-tertiary)',
                    borderLeft: `3px solid ${isCenter ? 'var(--accent-red)' : `var(--level-${log.level})`}`
                  }}
                >
                  <div className="flex flex-between flex-center mb-1">
                    <div className="flex flex-center gap-2">
                      <span className={`badge badge-${log.level}`}>{log.level}</span>
                      {log.hasAnomaly && (
                        <span className="badge badge-critical" style={{ fontSize: '0.65rem' }}>
                          ANOMALY
                        </span>
                      )}
                      {isCenter && (
                        <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>
                          FOCUS
                        </span>
                      )}
                    </div>
                    <span className="text-xs mono">{formatTimestamp(log.timestamp)}</span>
                  </div>
                  <p className="text-sm">{log.message}</p>
                  <div className="flex gap-2 mt-1 text-xs text-muted">
                    <span>{log.service}</span>
                    <span>•</span>
                    <span>{log.source}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {relatedLogs.length === 0 && (
          <div className="empty-state mt-4">
            <p>No related logs found in this time window</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default TimelineView;
