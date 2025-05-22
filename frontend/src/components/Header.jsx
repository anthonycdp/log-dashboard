import React from 'react';

const HEADER_STYLES = {
  background: 'var(--bg-secondary)',
  borderBottom: '1px solid var(--border-color)',
  padding: '0.75rem 0'
};

const TITLE_STYLES = {
  fontSize: '1.25rem',
  fontWeight: 700,
  color: 'var(--text-primary)'
};

const BADGE_STYLES = {
  marginLeft: '0.25rem',
  padding: '0.125rem 0.375rem'
};

function Header({ activeTab, onTabChange, tabs, alertCount }) {
  const navItems = buildNavItems(tabs, alertCount);

  return (
    <header style={HEADER_STYLES}>
      <div className="container flex flex-between flex-center">
        <div className="flex flex-center gap-4">
          <h1 style={TITLE_STYLES}>
            <span style={{ color: 'var(--accent-blue)' }}>Log</span>Dashboard
          </h1>
          <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>
            Anomaly Detection
          </span>
        </div>

        <nav className="flex flex-center gap-1">
          {navItems.map(renderNavItem(activeTab, onTabChange))}
        </nav>
      </div>
    </header>
  );
}

function buildNavItems(tabs, alertCount) {
  return [
    { id: tabs.DASHBOARD, label: 'Dashboard' },
    { id: tabs.LOGS, label: 'Logs' },
    { id: tabs.ALERTS, label: 'Alerts', badge: alertCount > 0 ? alertCount : null },
    { id: tabs.TIMELINE, label: 'Timeline', disabled: true }
  ];
}

function renderNavItem(activeTab, onTabChange) {
  return (item) => (
    <button
      key={item.id}
      className={`btn btn-sm ${activeTab === item.id ? 'btn-primary' : 'btn-secondary'}`}
      onClick={() => !item.disabled && onTabChange(item.id)}
      disabled={item.disabled}
      style={{ opacity: item.disabled ? 0.5 : 1 }}
    >
      {item.label}
      {item.badge && (
        <span className="badge badge-error" style={BADGE_STYLES}>
          {item.badge}
        </span>
      )}
    </button>
  );
}

export default Header;
