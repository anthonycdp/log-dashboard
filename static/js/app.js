/**
 * Security Log Dashboard - Frontend JavaScript
 */

// API Base URL
const API_BASE = '/api';

// State
let state = {
    logs: [],
    alerts: [],
    anomalies: [],
    currentPage: 0,
    pageSize: 50,
    totalLogs: 0,
    currentView: 'dashboard',
    charts: {},
    filters: {
        level: '',
        source: '',
        search: '',
        sourceIp: ''
    }
};

// Utility Functions
function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleTimeString();
}

function truncateText(text, maxLength = 100) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function getLevelClass(level) {
    const classes = {
        'INFO': 'INFO',
        'WARNING': 'WARNING',
        'ERROR': 'ERROR',
        'CRITICAL': 'CRITICAL',
        'DEBUG': 'DEBUG'
    };
    return classes[level] || 'INFO';
}

function getSeverityClass(severity) {
    return severity.toLowerCase();
}

// API Functions
async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        return null;
    }
}

// Navigation
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.dataset.view;
            switchView(view);
        });
    });

    // View all links
    document.querySelectorAll('.view-all').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const view = link.dataset.view;
            switchView(view);
        });
    });
}

function switchView(view) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === view);
    });

    // Update views
    document.querySelectorAll('.view').forEach(v => {
        v.classList.toggle('active', v.id === `${view}-view`);
    });

    // Update title
    const titles = {
        'dashboard': 'Dashboard Overview',
        'logs': 'Log Explorer',
        'alerts': 'Security Alerts',
        'anomalies': 'Anomaly Detection',
        'investigate': 'Incident Investigation',
        'timeline': 'Event Timeline'
    };
    document.getElementById('page-title').textContent = titles[view] || 'Dashboard';

    state.currentView = view;

    // Load view-specific data
    switch(view) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'logs':
            loadLogs();
            break;
        case 'alerts':
            loadAlerts();
            break;
        case 'anomalies':
            loadAnomalies();
            break;
    }
}

// Dashboard
async function loadDashboardData() {
    const [metrics, stats] = await Promise.all([
        fetchAPI('/dashboard/metrics'),
        fetchAPI('/statistics')
    ]);

    if (metrics) {
        updateMetrics(metrics);
        updateLogVolumeChart(metrics.log_trend);
        updateAlertsTrendChart(metrics.alert_trend);
    }

    if (stats) {
        updateLogLevelChart(stats.logs_by_level);
        updateTopIPsTable(stats.top_source_ips);
    }

    // Load recent alerts
    const alerts = await fetchAPI('/alerts?limit=5');
    if (alerts) {
        updateRecentAlerts(alerts.alerts);
    }

    updateLastUpdated();
}

function updateMetrics(metrics) {
    document.getElementById('metric-logs').textContent = metrics.total_logs_24h.toLocaleString();
    document.getElementById('metric-alerts').textContent = metrics.alerts_24h.toLocaleString();
    document.getElementById('metric-anomalies').textContent = metrics.anomalies_24h.toLocaleString();
    document.getElementById('metric-critical').textContent = metrics.critical_alerts.toLocaleString();

    // Update alert badge
    const badge = document.getElementById('alert-badge');
    badge.textContent = metrics.critical_alerts;
    badge.style.display = metrics.critical_alerts > 0 ? 'inline' : 'none';
}

function updateLastUpdated() {
    document.getElementById('last-updated-time').textContent = new Date().toLocaleTimeString();
}

// Charts
function initCharts() {
    // Log Volume Chart
    const logVolumeCtx = document.getElementById('log-volume-chart').getContext('2d');
    state.charts.logVolume = new Chart(logVolumeCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Log Count',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.1)' } },
                x: { grid: { display: false } }
            }
        }
    });

    // Alerts Trend Chart
    const alertsTrendCtx = document.getElementById('alerts-trend-chart').getContext('2d');
    state.charts.alertsTrend = new Chart(alertsTrendCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                backgroundColor: '#f97316',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.1)' } },
                x: { grid: { display: false } }
            }
        }
    });

    // Log Level Chart
    const logLevelCtx = document.getElementById('log-level-chart').getContext('2d');
    state.charts.logLevel = new Chart(logLevelCtx, {
        type: 'doughnut',
        data: {
            labels: ['INFO', 'WARNING', 'ERROR', 'CRITICAL', 'DEBUG'],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#3b82f6',
                    '#eab308',
                    '#f97316',
                    '#ef4444',
                    '#64748b'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8' }
                }
            }
        }
    });
}

function updateLogVolumeChart(trend) {
    if (!trend) return;

    const labels = trend.slice(0, 12).map(t => {
        const date = new Date(t.hour);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }).reverse();

    const data = trend.slice(0, 12).map(t => t.count).reverse();

    state.charts.logVolume.data.labels = labels;
    state.charts.logVolume.data.datasets[0].data = data;
    state.charts.logVolume.update();
}

function updateAlertsTrendChart(trend) {
    if (!trend) return;

    const labels = trend.slice(0, 12).map(t => {
        const date = new Date(t.hour);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }).reverse();

    const data = trend.slice(0, 12).map(t => t.count).reverse();

    state.charts.alertsTrend.data.labels = labels;
    state.charts.alertsTrend.data.datasets[0].data = data;
    state.charts.alertsTrend.update();
}

function updateLogLevelChart(levelData) {
    if (!levelData) return;

    const data = [
        levelData['INFO'] || 0,
        levelData['WARNING'] || 0,
        levelData['ERROR'] || 0,
        levelData['CRITICAL'] || 0,
        levelData['DEBUG'] || 0
    ];

    state.charts.logLevel.data.datasets[0].data = data;
    state.charts.logLevel.update();
}

function updateTopIPsTable(ips) {
    const tbody = document.querySelector('#top-ips-table tbody');
    if (!ips || !tbody) return;

    tbody.innerHTML = ips.map(ip => `
        <tr>
            <td><code>${ip.ip}</code></td>
            <td>${ip.count.toLocaleString()}</td>
            <td>
                <button class="action-btn" onclick="investigateIP('${ip.ip}')">Investigate</button>
            </td>
        </tr>
    `).join('');
}

function updateRecentAlerts(alerts) {
    const container = document.getElementById('recent-alerts-list');
    if (!alerts || !container) return;

    container.innerHTML = alerts.map(alert => `
        <div class="alert-item ${getSeverityClass(alert.severity)}" onclick="showAlertDetails('${alert.id}')">
            <div class="alert-header">
                <span class="alert-title">${escapeHtml(alert.title)}</span>
                <span class="alert-severity ${getSeverityClass(alert.severity)}">${alert.severity}</span>
            </div>
            <div class="alert-description">${escapeHtml(truncateText(alert.description, 150))}</div>
            <div class="alert-meta">
                <span>${formatTimestamp(alert.timestamp)}</span>
                <span>${alert.status}</span>
            </div>
        </div>
    `).join('');
}

// Logs View
async function loadLogs() {
    const params = new URLSearchParams();

    if (state.filters.level) params.append('levels', state.filters.level);
    if (state.filters.source) params.append('sources', state.filters.source);
    if (state.filters.search) params.append('query', state.filters.search);
    if (state.filters.sourceIp) params.append('source_ip', state.filters.sourceIp);
    params.append('limit', state.pageSize);
    params.append('offset', state.currentPage * state.pageSize);

    const data = await fetchAPI(`/logs?${params.toString()}`);

    if (data) {
        state.logs = data.results;
        state.totalLogs = data.total;
        renderLogsTable();
        updatePagination();
    }
}

function renderLogsTable() {
    const tbody = document.getElementById('logs-table-body');
    if (!tbody) return;

    tbody.innerHTML = state.logs.map(log => `
        <tr>
            <td>${formatTimestamp(log.timestamp)}</td>
            <td><span class="log-level ${getLevelClass(log.level)}">${log.level}</span></td>
            <td>${log.source}</td>
            <td>${log.source_ip || '-'}</td>
            <td class="log-message" title="${escapeHtml(log.message)}">${escapeHtml(truncateText(log.message, 80))}</td>
            <td>
                <button class="action-btn" onclick="showLogDetails('${log.id}')">Details</button>
                <button class="action-btn" onclick="investigateIP('${log.source_ip || ''}')">Investigate</button>
            </td>
        </tr>
    `).join('');
}

function updatePagination() {
    const info = document.getElementById('pagination-info');
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');

    if (!info) return;

    const start = state.currentPage * state.pageSize + 1;
    const end = Math.min((state.currentPage + 1) * state.pageSize, state.totalLogs);

    info.textContent = `Showing ${start}-${end} of ${state.totalLogs}`;

    prevBtn.disabled = state.currentPage === 0;
    nextBtn.disabled = end >= state.totalLogs;
}

// Alerts View
async function loadAlerts() {
    const status = document.getElementById('alert-filter-status').value;
    const severity = document.getElementById('alert-filter-severity').value;

    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    params.append('limit', 100);

    const data = await fetchAPI(`/alerts?${params.toString()}`);

    if (data) {
        state.alerts = data.alerts;
        renderAlertsList(data.alerts);
        renderAlertsStats(data.statistics);
    }
}

function renderAlertsList(alerts) {
    const container = document.getElementById('alerts-list');
    if (!container) return;

    if (alerts.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 2rem;">No alerts found</p>';
        return;
    }

    container.innerHTML = alerts.map(alert => `
        <div class="alert-item ${getSeverityClass(alert.severity)}" onclick="showAlertDetails('${alert.id}')">
            <div class="alert-header">
                <span class="alert-title">${escapeHtml(alert.title)}</span>
                <span class="alert-severity ${getSeverityClass(alert.severity)}">${alert.severity}</span>
            </div>
            <div class="alert-description">${escapeHtml(alert.description)}</div>
            <div class="alert-meta">
                <span>${formatTimestamp(alert.timestamp)}</span>
                <span>Status: ${alert.status}</span>
                ${alert.assigned_to ? `<span>Assigned: ${alert.assigned_to}</span>` : ''}
            </div>
        </div>
    `).join('');
}

function renderAlertsStats(stats) {
    const container = document.getElementById('alerts-stats');
    if (!container || !stats) return;

    container.innerHTML = `
        <div class="stat-item">
            <div class="stat-value">${stats.total}</div>
            <div class="stat-label">Total Alerts</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" style="color: var(--accent-red);">${stats.by_severity.critical || 0}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" style="color: var(--accent-orange);">${stats.by_severity.high || 0}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" style="color: var(--accent-green);">${stats.by_status.resolved || 0}</div>
            <div class="stat-label">Resolved</div>
        </div>
    `;
}

// Anomalies View
async function loadAnomalies() {
    const minScore = document.getElementById('anomaly-score-slider').value / 100;

    const data = await fetchAPI(`/anomalies?min_score=${minScore}&limit=100`);

    if (data) {
        state.anomalies = data.anomalies;
        renderAnomalies();
    }
}

function renderAnomalies() {
    const container = document.getElementById('anomalies-grid');
    if (!container) return;

    if (state.anomalies.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 2rem; grid-column: 1/-1;">No anomalies detected</p>';
        return;
    }

    container.innerHTML = state.anomalies.map(anomaly => `
        <div class="anomaly-card">
            <div class="anomaly-header">
                <span class="anomaly-type">${escapeHtml(anomaly.anomaly_type)}</span>
                <div class="anomaly-score">
                    <div class="score-bar">
                        <div class="score-fill" style="width: ${anomaly.score * 100}%"></div>
                    </div>
                    <span>${(anomaly.score * 100).toFixed(0)}%</span>
                </div>
            </div>
            <div class="anomaly-description">${escapeHtml(anomaly.description)}</div>
            <div class="anomaly-details">
                <div>Baseline: ${anomaly.baseline_value.toFixed(2)} | Observed: ${anomaly.observed_value.toFixed(2)}</div>
                <div>${formatTimestamp(anomaly.timestamp)}</div>
            </div>
        </div>
    `).join('');
}

async function runAnomalyDetection() {
    const btn = document.getElementById('run-detection');
    btn.disabled = true;
    btn.textContent = 'Running...';

    const result = await fetchAPI('/anomalies/detect', { method: 'POST' });

    btn.disabled = false;
    btn.textContent = 'Run Detection';

    if (result) {
        alert(`Detection complete!\nAnomalies found: ${result.anomalies_detected}\nAlerts generated: ${result.alerts_generated}`);
        loadAnomalies();
    }
}

// Investigation
async function runInvestigation() {
    const ip = document.getElementById('investigate-ip').value;
    const user = document.getElementById('investigate-user').value;
    const start = document.getElementById('investigate-start').value;
    const end = document.getElementById('investigate-end').value;

    if (!ip && !user) {
        alert('Please enter either an IP address or username to investigate.');
        return;
    }

    const params = new URLSearchParams();
    if (ip) params.append('source_ip', ip);
    if (user) params.append('user', user);
    if (start) params.append('start_time', new Date(start).toISOString());
    if (end) params.append('end_time', new Date(end).toISOString());

    const result = await fetchAPI(`/investigate?${params.toString()}`);

    if (result) {
        renderInvestigationResults(result);
    }
}

function renderInvestigationResults(result) {
    const container = document.getElementById('investigation-results');
    container.style.display = 'block';

    // Summary
    const summary = document.getElementById('investigation-summary');
    summary.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h3>Investigation Results</h3>
            <span class="risk-badge ${result.risk_assessment.risk_level}">${result.risk_assessment.risk_level.toUpperCase()} RISK</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
            <div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Total Logs</div>
                <div style="font-size: 1.25rem; font-weight: 600;">${result.summary.total_logs}</div>
            </div>
            <div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Related Alerts</div>
                <div style="font-size: 1.25rem; font-weight: 600;">${result.summary.total_alerts}</div>
            </div>
            <div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Time Range</div>
                <div style="font-size: 0.875rem;">
                    ${new Date(result.summary.time_range.start).toLocaleString()} - ${new Date(result.summary.time_range.end).toLocaleString()}
                </div>
            </div>
        </div>
        <div style="margin-top: 1rem;">
            <strong>Risk Factors:</strong>
            <ul style="margin: 0.5rem 0; padding-left: 1.5rem; color: var(--text-secondary);">
                ${result.risk_assessment.factors.map(f => `<li>${f}</li>`).join('')}
            </ul>
        </div>
    `;

    // Timeline
    const timeline = document.getElementById('investigation-timeline');
    if (result.timeline.length > 0) {
        timeline.innerHTML = `
            <h4 style="margin-bottom: 1rem;">Event Timeline</h4>
            ${result.timeline.slice(0, 50).map(event => `
                <div class="timeline-item">
                    <div class="timeline-time">${formatTimestamp(event.timestamp)}</div>
                    <div class="timeline-content">
                        <div class="timeline-type ${event.type}">${event.type}</div>
                        <div>${event.type === 'alert' ? event.title : escapeHtml(truncateText(event.message, 100))}</div>
                    </div>
                </div>
            `).join('')}
        `;
    } else {
        timeline.innerHTML = '<p style="color: var(--text-muted);">No timeline events found.</p>';
    }
}

// Timeline View
async function loadTimeline() {
    const ip = document.getElementById('timeline-ip').value;
    const user = document.getElementById('timeline-user').value;

    const params = new URLSearchParams();
    if (ip) params.append('source_ip', ip);
    if (user) params.append('user', user);

    const data = await fetchAPI(`/logs/timeline/events?${params.toString()}`);

    if (data) {
        renderTimeline(data.events);
    }
}

function renderTimeline(events) {
    const container = document.getElementById('timeline-container');

    if (events.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-muted);">No events found for the specified criteria.</p>';
        return;
    }

    container.innerHTML = `
        <h3 style="margin-bottom: 1rem;">${events.length} Events Found</h3>
        ${events.slice(0, 100).map(event => `
            <div class="timeline-item">
                <div class="timeline-time">${formatTimestamp(event.timestamp)}</div>
                <div class="timeline-content">
                    <div class="timeline-type log">${event.event_type}</div>
                    <div>${escapeHtml(event.description)}</div>
                    ${event.related_ips.length > 0 ? `<small style="color: var(--text-muted);">IPs: ${event.related_ips.join(', ')}</small>` : ''}
                    ${event.related_users.length > 0 ? `<small style="color: var(--text-muted);">Users: ${event.related_users.join(', ')}</small>` : ''}
                </div>
            </div>
        `).join('')}
    `;
}

// Modal Functions
function showLogDetails(logId) {
    const log = state.logs.find(l => l.id === logId);
    if (!log) return;

    const modal = document.getElementById('log-modal');
    const body = document.getElementById('log-modal-body');

    body.innerHTML = `
        <div class="detail-grid">
            <div class="detail-item">
                <span class="detail-label">Timestamp</span>
                <span class="detail-value">${formatTimestamp(log.timestamp)}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Level</span>
                <span class="detail-value"><span class="log-level ${getLevelClass(log.level)}">${log.level}</span></span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Source</span>
                <span class="detail-value">${log.source}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Hostname</span>
                <span class="detail-value">${log.hostname || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Source IP</span>
                <span class="detail-value">${log.source_ip || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Destination IP</span>
                <span class="detail-value">${log.dest_ip || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Source Port</span>
                <span class="detail-value">${log.source_port || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Destination Port</span>
                <span class="detail-value">${log.dest_port || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Protocol</span>
                <span class="detail-value">${log.protocol || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">User</span>
                <span class="detail-value">${log.user || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Process</span>
                <span class="detail-value">${log.process || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Tags</span>
                <span class="detail-value">${log.tags.join(', ') || '-'}</span>
            </div>
            <div class="detail-item" style="grid-column: 1 / -1;">
                <span class="detail-label">Message</span>
                <span class="detail-value">${escapeHtml(log.message)}</span>
            </div>
            ${Object.keys(log.metadata || {}).length > 0 ? `
                <div class="detail-item" style="grid-column: 1 / -1;">
                    <span class="detail-label">Metadata</span>
                    <pre style="background: var(--bg-tertiary); padding: 0.5rem; border-radius: 4px; overflow-x: auto;">${JSON.stringify(log.metadata, null, 2)}</pre>
                </div>
            ` : ''}
        </div>
    `;

    modal.classList.add('active');
}

async function showAlertDetails(alertId) {
    const alert = state.alerts.find(a => a.id === alertId);
    if (!alert) return;

    const modal = document.getElementById('alert-modal');
    const body = document.getElementById('alert-modal-body');
    const footer = document.getElementById('alert-modal-footer');

    body.innerHTML = `
        <div class="detail-grid">
            <div class="detail-item">
                <span class="detail-label">Timestamp</span>
                <span class="detail-value">${formatTimestamp(alert.timestamp)}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Severity</span>
                <span class="detail-value"><span class="alert-severity ${getSeverityClass(alert.severity)}">${alert.severity}</span></span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Status</span>
                <span class="detail-value">${alert.status}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Source</span>
                <span class="detail-value">${alert.source}</span>
            </div>
            <div class="detail-item" style="grid-column: 1 / -1;">
                <span class="detail-label">Title</span>
                <span class="detail-value">${escapeHtml(alert.title)}</span>
            </div>
            <div class="detail-item" style="grid-column: 1 / -1;">
                <span class="detail-label">Description</span>
                <span class="detail-value">${escapeHtml(alert.description)}</span>
            </div>
            ${alert.assigned_to ? `
                <div class="detail-item">
                    <span class="detail-label">Assigned To</span>
                    <span class="detail-value">${alert.assigned_to}</span>
                </div>
            ` : ''}
            ${alert.resolved_at ? `
                <div class="detail-item">
                    <span class="detail-label">Resolved At</span>
                    <span class="detail-value">${formatTimestamp(alert.resolved_at)}</span>
                </div>
            ` : ''}
            ${Object.keys(alert.indicators || {}).length > 0 ? `
                <div class="detail-item" style="grid-column: 1 / -1;">
                    <span class="detail-label">Indicators</span>
                    <pre style="background: var(--bg-tertiary); padding: 0.5rem; border-radius: 4px; overflow-x: auto;">${JSON.stringify(alert.indicators, null, 2)}</pre>
                </div>
            ` : ''}
        </div>
    `;

    footer.innerHTML = `
        <button class="btn-secondary" onclick="updateAlertStatus('${alert.id}', 'acknowledged')">Acknowledge</button>
        <button class="btn-secondary" onclick="updateAlertStatus('${alert.id}', 'investigating')">Investigate</button>
        <button class="btn-primary" onclick="updateAlertStatus('${alert.id}', 'resolved')">Resolve</button>
    `;

    modal.classList.add('active');
}

async function updateAlertStatus(alertId, status) {
    const result = await fetchAPI(`/alerts/${alertId}/status?status=${status}`, { method: 'PUT' });

    if (result) {
        document.getElementById('alert-modal').classList.remove('active');
        loadAlerts();
    }
}

function investigateIP(ip) {
    if (!ip) return;

    // Switch to investigation view
    switchView('investigate');

    // Pre-fill IP
    document.getElementById('investigate-ip').value = ip;
}

// Utility
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Event Listeners
function initEventListeners() {
    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', () => {
        switch (state.currentView) {
            case 'dashboard':
                loadDashboardData();
                break;
            case 'logs':
                loadLogs();
                break;
            case 'alerts':
                loadAlerts();
                break;
            case 'anomalies':
                loadAnomalies();
                break;
        }
    });

    // Theme toggle
    document.getElementById('theme-toggle').addEventListener('click', () => {
        document.body.toggleAttribute('data-theme');
        const theme = document.body.getAttribute('data-theme') || 'dark';
        document.body.setAttribute('data-theme', theme === 'light' ? '' : 'light');
    });

    // Log filters
    document.getElementById('apply-filters').addEventListener('click', () => {
        state.filters.level = document.getElementById('filter-level').value;
        state.filters.source = document.getElementById('filter-source').value;
        state.filters.search = document.getElementById('filter-search').value;
        state.filters.sourceIp = document.getElementById('filter-ip').value;
        state.currentPage = 0;
        loadLogs();
    });

    document.getElementById('clear-filters').addEventListener('click', () => {
        document.getElementById('filter-level').value = '';
        document.getElementById('filter-source').value = '';
        document.getElementById('filter-search').value = '';
        document.getElementById('filter-ip').value = '';
        state.filters = { level: '', source: '', search: '', sourceIp: '' };
        state.currentPage = 0;
        loadLogs();
    });

    // Pagination
    document.getElementById('prev-page').addEventListener('click', () => {
        if (state.currentPage > 0) {
            state.currentPage--;
            loadLogs();
        }
    });

    document.getElementById('next-page').addEventListener('click', () => {
        state.currentPage++;
        loadLogs();
    });

    // Alert filters
    document.getElementById('refresh-alerts').addEventListener('click', loadAlerts);
    document.getElementById('alert-filter-status').addEventListener('change', loadAlerts);
    document.getElementById('alert-filter-severity').addEventListener('change', loadAlerts);

    // Anomaly controls
    document.getElementById('anomaly-score-slider').addEventListener('input', (e) => {
        document.getElementById('anomaly-score-value').textContent = (e.target.value / 100).toFixed(2);
    });

    document.getElementById('run-detection').addEventListener('click', runAnomalyDetection);
    document.getElementById('refresh-anomalies').addEventListener('click', loadAnomalies);

    // Investigation
    document.getElementById('run-investigation').addEventListener('click', runInvestigation);

    // Timeline
    document.getElementById('load-timeline').addEventListener('click', loadTimeline);

    // Global search
    document.getElementById('global-search').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const query = e.target.value;
            state.filters.search = query;
            switchView('logs');
            document.getElementById('filter-search').value = query;
            loadLogs();
        }
    });

    // Modal close buttons
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            btn.closest('.modal').classList.remove('active');
        });
    });

    // Close modal on outside click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });

    // Set default investigation times
    const now = new Date();
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    document.getElementById('investigate-start').value = yesterday.toISOString().slice(0, 16);
    document.getElementById('investigate-end').value = now.toISOString().slice(0, 16);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initCharts();
    initEventListeners();
    loadDashboardData();

    // Auto-refresh every 30 seconds
    setInterval(() => {
        if (state.currentView === 'dashboard') {
            loadDashboardData();
        }
    }, 30000);
});
