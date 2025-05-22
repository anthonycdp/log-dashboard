import React from 'react';
import { formatNumber } from '../utils/formatters';

const ALERTS_CARD_INDEX = 3;

function getAlertSeverityColor(alertCount) {
  return alertCount > 0 ? 'var(--severity-critical)' : 'var(--accent-green)';
}

function renderLoadingPlaceholders() {
  return (
    <>
      {[1, 2, 3, 4].map(i => (
        <div key={i} className="card">
          <div className="loading">
            <div className="spinner" />
          </div>
        </div>
      ))}
    </>
  );
}

function renderSeverityBadges(bySeverity) {
  if (!bySeverity) return null;

  return (
    <div className="flex gap-2 mt-2">
      {bySeverity.critical > 0 && (
        <span className="badge badge-critical">
          {bySeverity.critical} critical
        </span>
      )}
      {bySeverity.high > 0 && (
        <span className="badge badge-high">
          {bySeverity.high} high
        </span>
      )}
    </div>
  );
}

function StatsCards({ stats }) {
  if (!stats) {
    return renderLoadingPlaceholders();
  }

  const cards = [
    {
      label: 'Total Logs',
      value: formatNumber(stats.logs.total),
      color: 'var(--accent-blue)',
      icon: '📊'
    },
    {
      label: 'Errors',
      value: formatNumber(stats.logs.byLevel.error || 0),
      color: 'var(--level-error)',
      icon: '❌'
    },
    {
      label: 'Warnings',
      value: formatNumber(stats.logs.byLevel.warn || 0),
      color: 'var(--level-warn)',
      icon: '⚠️'
    },
    {
      label: 'Active Alerts',
      value: formatNumber(stats.alerts.active || 0),
      color: getAlertSeverityColor(stats.alerts.active),
      icon: '🔔'
    }
  ];

  return (
    <>
      {cards.map((card, index) => (
        <div key={index} className="card stat-card">
          <div className="flex flex-between flex-center">
            <span style={{ fontSize: '1.5rem' }}>{card.icon}</span>
            <span className="stat-value" style={{ color: card.color }}>
              {card.value}
            </span>
          </div>
          <span className="stat-label">{card.label}</span>
          {index === ALERTS_CARD_INDEX && renderSeverityBadges(stats.alerts.bySeverity)}
        </div>
      ))}
    </>
  );
}

export default StatsCards;
