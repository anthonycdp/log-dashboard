import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { useApi } from '../hooks/useApi';
import { formatTimestamp, truncateText } from '../utils/formatters';

const POLLING_INTERVAL_MS = 5000;
const LOGS_CONTAINER_MAX_HEIGHT = '500px';
const MESSAGE_TRUNCATE_LENGTH = 150;
const LOG_ID_DISPLAY_LENGTH = 12;

const LEVEL_OPTIONS = [
  { value: '', label: 'All Levels' },
  { value: 'error', label: 'Error' },
  { value: 'warn', label: 'Warning' },
  { value: 'info', label: 'Info' },
  { value: 'debug', label: 'Debug' }
];

const ANOMALY_OPTIONS = [
  { value: '', label: 'All Logs' },
  { value: 'true', label: 'With Anomalies' },
  { value: 'false', label: 'Normal Only' }
];

const EMPTY_FILTERS = {
  level: '',
  service: '',
  search: '',
  hasAnomaly: ''
};

function LogsTable({ filters, onFiltersChange, limit, onLogSelect }) {
  const [localFilters, setLocalFilters] = useState({
    ...EMPTY_FILTERS,
    level: filters?.level || '',
    service: filters?.service || '',
    search: filters?.search || ''
  });

  const { data, loading, error, execute } = useApi(
    () => api.getLogs({
      ...localFilters,
      limit: limit || 50,
      offset: 0
    }),
    [localFilters.level, localFilters.service, localFilters.search, localFilters.hasAnomaly]
  );

  useEffect(() => {
    const interval = setInterval(execute, POLLING_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [execute]);

  const handleFilterChange = (key, value) => {
    const updatedFilters = { ...localFilters, [key]: value };
    setLocalFilters(updatedFilters);
    onFiltersChange?.(updatedFilters);
  };

  const clearFilters = () => {
    setLocalFilters(EMPTY_FILTERS);
    onFiltersChange?.(EMPTY_FILTERS);
  };

  if (error) {
    return <div className="empty-state text-muted">Error loading logs: {error}</div>;
  }

  return (
    <div>
      <FilterBar
        filters={localFilters}
        onFilterChange={handleFilterChange}
        onClear={clearFilters}
        onRefresh={execute}
        loading={loading}
      />

      {loading && !data && <LoadingSpinner />}

      {data?.logs?.length === 0 && <EmptyState />}

      <LogsList
        logs={data?.logs}
        onLogSelect={onLogSelect}
      />

      {data?.pagination?.hasMore && (
        <PaginationInfo
          currentCount={data.logs.length}
          totalCount={data.pagination.total}
        />
      )}
    </div>
  );
}

function FilterBar({ filters, onFilterChange, onClear, onRefresh, loading }) {
  return (
    <div className="flex gap-2 mb-4" style={{ flexWrap: 'wrap' }}>
      <SelectFilter
        value={filters.level}
        onChange={(e) => onFilterChange('level', e.target.value)}
        options={LEVEL_OPTIONS}
        minWidth="120px"
      />

      <input
        type="text"
        placeholder="Filter by service..."
        value={filters.service}
        onChange={(e) => onFilterChange('service', e.target.value)}
        style={{ minWidth: '150px' }}
      />

      <input
        type="text"
        placeholder="Search logs..."
        value={filters.search}
        onChange={(e) => onFilterChange('search', e.target.value)}
        style={{ minWidth: '200px' }}
      />

      <SelectFilter
        value={filters.hasAnomaly}
        onChange={(e) => onFilterChange('hasAnomaly', e.target.value)}
        options={ANOMALY_OPTIONS}
        minWidth="150px"
      />

      <button className="btn btn-secondary btn-sm" onClick={onClear}>
        Clear
      </button>

      <button className="btn btn-primary btn-sm" onClick={onRefresh} disabled={loading}>
        {loading ? 'Refreshing...' : 'Refresh'}
      </button>
    </div>
  );
}

function SelectFilter({ value, onChange, options, minWidth }) {
  return (
    <select value={value} onChange={onChange} style={{ minWidth }}>
      {options.map(option => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

function LoadingSpinner() {
  return (
    <div className="loading">
      <div className="spinner" />
    </div>
  );
}

function EmptyState() {
  return (
    <div className="empty-state">
      <p>No logs found</p>
      <p className="text-sm text-muted">Start the simulation to generate logs</p>
    </div>
  );
}

function LogsList({ logs, onLogSelect }) {
  if (!logs) return null;

  return (
    <div style={{ maxHeight: LOGS_CONTAINER_MAX_HEIGHT, overflowY: 'auto' }}>
      {logs.map(log => (
        <LogEntry
          key={log.id}
          log={log}
          onSelect={onLogSelect}
        />
      ))}
    </div>
  );
}

function LogEntry({ log, onSelect }) {
  const handleClick = () => onSelect?.(log);

  return (
    <div
      className={`log-entry ${log.level} ${log.hasAnomaly ? 'anomaly' : ''}`}
      onClick={handleClick}
      style={{ cursor: onSelect ? 'pointer' : 'default' }}
    >
      <div className="flex flex-between flex-center mb-1">
        <div className="flex flex-center gap-2">
          <span className={`badge badge-${log.level}`}>{log.level}</span>
          {log.hasAnomaly && (
            <span className="badge badge-critical">ANOMALY</span>
          )}
          <span className="text-xs text-muted mono">{log.service}</span>
        </div>
        <span className="text-xs text-muted">{formatTimestamp(log.timestamp)}</span>
      </div>
      <p className="text-sm" style={{ color: 'var(--text-primary)' }}>
        {truncateText(log.message, MESSAGE_TRUNCATE_LENGTH)}
      </p>
      <div className="flex gap-2 mt-1">
        <span className="text-xs text-muted">source: {log.source}</span>
        <span className="text-xs text-muted">id: {log.id.slice(0, LOG_ID_DISPLAY_LENGTH)}...</span>
      </div>
    </div>
  );
}

function PaginationInfo({ currentCount, totalCount }) {
  return (
    <div className="text-center mt-4">
      <span className="text-sm text-muted">
        Showing {currentCount} of {totalCount} logs
      </span>
    </div>
  );
}

export default LogsTable;
