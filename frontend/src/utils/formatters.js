import { format, formatDistanceToNow, parseISO } from 'date-fns';

const THRESHOLD_K = 1000;
const MILLION_THRESHOLD = 1000000;

function parseDate(timestamp) {
  return typeof timestamp === 'string' ? parseISO(timestamp) : timestamp;
}

export function formatTimestamp(timestamp) {
  return format(parseDate(timestamp), 'yyyy-MM-dd HH:mm:ss');
}

export function formatRelativeTime(timestamp) {
  return formatDistanceToNow(parseDate(timestamp), { addSuffix: true });
}

export function formatShortTime(timestamp) {
  return format(parseDate(timestamp), 'HH:mm:ss');
}

export function truncateText(text, maxLength = 100) {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
}

export function getLevelColor(level) {
  const colors = {
    error: 'var(--level-error)',
    warn: 'var(--level-warn)',
    info: 'var(--level-info)',
    debug: 'var(--level-debug)'
  };
  return colors[level] || 'var(--text-secondary)';
}

export function getSeverityColor(severity) {
  const colors = {
    critical: 'var(--severity-critical)',
    high: 'var(--severity-high)',
    medium: 'var(--severity-medium)',
    low: 'var(--severity-low)'
  };
  return colors[severity] || 'var(--text-secondary)';
}

export function formatNumber(num) {
  if (num >= MILLION_THRESHOLD) return (num / MILLION_THRESHOLD).toFixed(1) + 'M';
  if (num >= THRESHOLD_K) return (num / THRESHOLD_K).toFixed(1) + 'K';
  return num.toString();
}

export function formatPercent(value) {
  return (value * 100).toFixed(1) + '%';
}
