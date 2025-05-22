import React, { useState, useEffect } from 'react';
import api from '../services/api';

function SimulationControl({ onToggle }) {
  const [isRunning, setIsRunning] = useState(false);
  const [simulationInterval, setSimulationInterval] = useState(2000);
  const [anomalyRate, setAnomalyRate] = useState(0.1);
  const [loading, setLoading] = useState(false);

  const handleStart = async () => {
    setLoading(true);
    try {
      await api.startSimulation(simulationInterval, anomalyRate);
      setIsRunning(true);
      onToggle?.();
    } catch (err) {
      console.error('Failed to start simulation:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      await api.stopSimulation();
      setIsRunning(false);
      onToggle?.();
    } catch (err) {
      console.error('Failed to stop simulation:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card mb-4">
      <div className="card-header">
        <h3 className="card-title">Log Simulator</h3>
        <span className={`badge ${isRunning ? 'badge-info' : 'badge-debug'}`}>
          {isRunning ? 'Running' : 'Stopped'}
        </span>
      </div>

      <div className="flex flex-between flex-center gap-4" style={{ flexWrap: 'wrap' }}>
        <div className="flex flex-center gap-4">
          <div className="flex flex-center gap-2">
            <label className="text-sm text-muted">Interval (ms):</label>
            <input
              type="number"
              value={simulationInterval}
              onChange={(e) => setSimulationInterval(Number(e.target.value))}
              disabled={isRunning}
              style={{ width: '100px' }}
              min={500}
              max={10000}
            />
          </div>

          <div className="flex flex-center gap-2">
            <label className="text-sm text-muted">Anomaly Rate:</label>
            <input
              type="range"
              value={anomalyRate}
              onChange={(e) => setAnomalyRate(Number(e.target.value))}
              disabled={isRunning}
              min={0}
              max={0.5}
              step={0.05}
              style={{ width: '100px' }}
            />
            <span className="text-sm">{(anomalyRate * 100).toFixed(0)}%</span>
          </div>
        </div>

        <div className="flex gap-2">
          {!isRunning ? (
            <button
              className="btn btn-success"
              onClick={handleStart}
              disabled={loading}
            >
              {loading ? 'Starting...' : '▶ Start Simulation'}
            </button>
          ) : (
            <button
              className="btn btn-danger"
              onClick={handleStop}
              disabled={loading}
            >
              {loading ? 'Stopping...' : '■ Stop Simulation'}
            </button>
          )}

          <button
            className="btn btn-secondary"
            onClick={onToggle}
            title="Refresh data"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      <p className="text-xs text-muted mt-2">
        The simulator generates realistic log entries with configurable anomaly rates.
        Anomalies trigger automatic detection and alert creation.
      </p>
    </div>
  );
}

export default SimulationControl;
