# Log Dashboard - Anomaly Detection & Incident Investigation

A comprehensive log monitoring dashboard with real-time anomaly detection, alert management, and incident timeline investigation capabilities.

## Features

- **Real-time Log Ingestion**: Simulated log pipeline with configurable rates
- **Multi-Method Anomaly Detection**:
  - Statistical: Error burst detection, frequency spike analysis, pattern recognition
  - ML-based: Feature-weighted isolation scoring
- **Alert System**: Severity-based alerts (critical, high, medium, low) with acknowledge/resolve workflow
- **Interactive Dashboard**: Real-time charts, statistics, and log explorer
- **Timeline View**: Investigate incidents by viewing related logs in a time window
- **Search & Filter**: Full-text search, level/service filtering, anomaly filtering
- **Docker Support**: Production-ready containerization

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React + Vite)                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │Dashboard │ │  Logs    │ │ Alerts   │ │   Timeline   │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬───────┘   │
└───────┼────────────┼────────────┼──────────────┼───────────┘
        │            │            │              │
        └────────────┴─────┬──────┴──────────────┘
                           │ HTTP/REST
┌──────────────────────────┴──────────────────────────────────┐
│                  Backend API (Express.js)                    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Routes                            │    │
│  │  /api/logs  /api/alerts  /api/stats  /api/anomaly   │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                   │
│  ┌───────────────────────┴─────────────────────────────┐    │
│  │                 Services                             │    │
│  │  ┌─────────────┐  ┌──────────────────────────────┐ │    │
│  │  │ LogSimulator│  │     AnomalyDetector          │ │    │
│  │  └─────────────┘  │  • Error Burst Detection     │ │    │
│  │                   │  • Frequency Spike (Z-score)  │ │    │
│  │                   │  • Pattern Recognition        │ │    │
│  │                   │  • ML Feature Scoring         │ │    │
│  │                   └──────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                   │
│  ┌───────────────────────┴─────────────────────────────┐    │
│  │                   Models                             │    │
│  │  ┌─────────────┐  ┌─────────────────────────────┐   │    │
│  │  │  LogStore   │  │       AlertStore            │   │    │
│  │  │ (In-memory) │  │     (In-memory)             │   │    │
│  │  └─────────────┘  └─────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- Docker (optional)

### Development Setup

1. **Install dependencies**:
```bash
# Backend
cd backend && npm install

# Frontend
cd ../frontend && npm install
```

2. **Start the backend** (in one terminal):
```bash
cd backend
npm run dev
```

3. **Start the frontend** (in another terminal):
```bash
cd frontend
npm run dev
```

4. **Access the dashboard**: http://localhost:3000

### Docker Setup

```bash
# Development (with hot reload)
docker-compose up frontend-dev backend-dev

# Production build
docker-compose up backend
```

## API Reference

### Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/logs` | List logs with filters |
| GET | `/api/logs/:id` | Get single log |
| GET | `/api/logs/:id/timeline` | Get related logs for timeline |
| GET | `/api/logs/timeseries` | Get time series data |
| POST | `/api/logs` | Create log entry |
| DELETE | `/api/logs` | Clear all logs |

**Query Parameters for GET /api/logs**:
- `level` - Filter by log level (error, warn, info, debug)
- `service` - Filter by service name
- `source` - Filter by source
- `search` - Full-text search
- `hasAnomaly` - Filter by anomaly status (true/false)
- `startTime` / `endTime` - Time range filter (ISO 8601)
- `limit` / `offset` - Pagination
- `sortBy` / `sortOrder` - Sorting

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts |
| GET | `/api/alerts/summary` | Alert statistics |
| GET | `/api/alerts/:id` | Get single alert |
| POST | `/api/alerts/:id/acknowledge` | Acknowledge alert |
| POST | `/api/alerts/:id/resolve` | Resolve alert |

### Statistics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Overall statistics |
| GET | `/api/stats/levels` | Log level statistics |
| GET | `/api/stats/services` | Service statistics |

### Anomaly Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/anomaly/detectors` | List detectors |
| GET | `/api/anomaly/config` | Get configuration |
| PUT | `/api/anomaly/config` | Update configuration |
| POST | `/api/anomaly/analyze` | Analyze single log |
| GET | `/api/anomaly/stats` | Detection statistics |

### Simulation

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/simulation/start` | Start log simulation |
| POST | `/api/simulation/stop` | Stop simulation |

### Ingestion

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ingest` | Bulk log ingestion |

## Anomaly Detection Algorithms

### 1. Error Burst Detection
Detects sudden spikes in error rates using a sliding window approach.

```
Error Rate = Error Count / Total Logs in Window
Anomaly if: Error Rate > Threshold (default: 30%)
```

### 2. Frequency Spike Detection (Z-Score)
Identifies unusual log frequency patterns using statistical analysis.

```
Z-Score = (Current Frequency - Mean) / Standard Deviation
Anomaly if: Z-Score > Threshold (default: 3)
```

### 3. Pattern Anomaly Detection
Matches log messages against suspicious patterns and calculates rarity scores.

**Tracked Patterns**:
- Error/exception patterns
- Availability issues (timeout, unavailable)
- Security patterns (unauthorized, forbidden)
- Resource patterns (memory, OOM)
- Performance patterns (slow, latency)

### 4. ML-Based Detection
Feature-weighted scoring inspired by Isolation Forest concepts.

**Features**:
- Log level weight (0.3)
- Frequency score (0.25)
- Time pattern (0.2) - unusual hours detection
- Message entropy (0.25) - randomness measure

```
Anomaly Score = Σ(Feature Value × Feature Weight)
Anomaly if: Score > Threshold (default: 0.7)
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3001 | Backend server port |
| `NODE_ENV` | development | Environment mode |

### Anomaly Detection Config

```javascript
{
  errorRateWindow: 60000,      // 1 minute
  errorRateThreshold: 0.3,     // 30%
  errorRateMinSample: 10,
  frequencyWindow: 60000,      // 1 minute
  frequencyThreshold: 3,       // Z-score
  contaminationRate: 0.1,
  featureWeights: {
    logLevel: 0.3,
    frequency: 0.25,
    timePattern: 0.2,
    messageEntropy: 0.25
  }
}
```

## Testing

```bash
# Run all tests
cd backend
npm test

# Run with watch mode
npm run test:watch

# Run specific test file
npm test -- tests/anomaly.test.js
```

### Test Coverage

- **API Tests**: All endpoints, error handling, pagination
- **Unit Tests**: LogStore, AlertStore operations
- **Anomaly Tests**: Detection algorithms, severity calculation, feature extraction

## Project Structure

```
log-dashboard/
├── backend/
│   ├── src/
│   │   ├── index.js           # App entry point
│   │   ├── config/            # Configuration constants
│   │   │   └── constants.js
│   │   ├── routes/            # API routes
│   │   │   ├── logs.js
│   │   │   ├── alerts.js
│   │   │   ├── stats.js
│   │   │   ├── anomaly.js
│   │   │   └── ingest.js
│   │   ├── services/          # Business logic
│   │   │   ├── AnomalyDetector.js
│   │   │   └── LogSimulator.js
│   │   ├── models/            # Data models
│   │   │   ├── LogStore.js
│   │   │   └── AlertStore.js
│   │   └── middleware/        # Express middleware
│   │       ├── errorHandler.js
│   │       └── requestLogger.js
│   │   └── utils/             # Utility functions
│   │       └── helpers.js
│   ├── tests/                 # Test files
│   └── package.json
├── data/                      # Sample data files
│   └── sample_logs.json
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # Main app component
│   │   ├── components/        # React components
│   │   │   ├── Header.jsx
│   │   │   ├── StatsCards.jsx
│   │   │   ├── LogsChart.jsx
│   │   │   ├── LogsTable.jsx
│   │   │   ├── AlertsPanel.jsx
│   │   │   ├── TimelineView.jsx
│   │   │   └── SimulationControl.jsx
│   │   ├── hooks/             # Custom hooks
│   │   │   └── useApi.js
│   │   ├── services/          # API client
│   │   │   └── api.js
│   │   ├── utils/             # Utilities
│   │   │   └── formatters.js
│   │   └── styles/
│   │       └── global.css
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## Usage Examples

### Starting a Simulation

```javascript
// Start generating logs
POST /api/simulation/start
{
  "interval": 2000,      // Log every 2 seconds
  "anomalyRate": 0.1     // 10% anomaly rate
}
```

### Ingesting Custom Logs

```javascript
POST /api/ingest
{
  "logs": [
    {
      "level": "error",
      "message": "Database connection failed",
      "service": "api-gateway",
      "source": "database"
    },
    {
      "level": "warn",
      "message": "High memory usage",
      "service": "monitoring",
      "source": "system"
    }
  ]
}
```

### Searching Logs

```bash
# Find all errors in the last hour
GET /api/logs?level=error&startTime=2024-01-01T00:00:00Z

# Full-text search
GET /api/logs?search=timeout

# Filter anomalies only
GET /api/logs?hasAnomaly=true
```

## Performance Considerations

- **In-memory storage**: Suitable for demo/development; use a database for production
- **Log limit**: 100,000 logs max before oldest 10% are pruned
- **Alert limit**: 10,000 alerts max before pruning
- **Real-time updates**: 5-second polling interval by default

## Future Enhancements

- [ ] Database persistence (PostgreSQL/MongoDB)
- [ ] WebSocket for real-time updates
- [ ] Custom alert rules and thresholds
- [ ] Export logs (CSV, JSON)
- [ ] User authentication
- [ ] Multi-tenant support
- [ ] Advanced ML models (LSTM, transformers)

## License

MIT License - feel free to use for your projects!

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `npm test`
5. Submit a pull request

---

Built with Node.js, Express, React, and Chart.js
