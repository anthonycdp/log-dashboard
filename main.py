"""
Security Log Dashboard - FastAPI Backend
Main application entry point with all API endpoints.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import json
import uuid
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from models import (
    LogEntry, Alert, AnomalyResult, SearchQuery, SearchResponse,
    LogStatistics, DashboardMetrics, TimelineEvent, LogLevel, LogSource,
    AlertSeverity
)
from anomaly_detection import AnomalyDetector, BaselineCalculator
from alert_manager import AlertManager


# Global state
log_store: Dict[str, LogEntry] = {}
alert_manager = AlertManager()
anomaly_detector = AnomalyDetector()
baseline_calculator = BaselineCalculator()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load sample data on startup."""
    load_sample_data()
    yield


app = FastAPI(
    title="Security Log Dashboard",
    description="A comprehensive security log aggregation and visualization dashboard",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")


def load_sample_data():
    """Load sample log data from JSON file."""
    global log_store

    data_file = Path("data/sample_logs.json")
    if data_file.exists():
        with open(data_file, "r") as f:
            data = json.load(f)

        for log_data in data.get("logs", []):
            log_data["timestamp"] = datetime.fromisoformat(log_data["timestamp"])
            log = LogEntry(**log_data)
            log_store[log.id] = log

        print(f"Loaded {len(log_store)} sample logs")

        # Run initial anomaly detection
        logs_list = list(log_store.values())
        anomalies = anomaly_detector.detect_anomalies(logs_list)

        # Process anomalies through alert manager
        alert_manager.process_anomalies(anomalies, logs_list)

        # Process logs for rule-based alerts
        alert_manager.process_logs(logs_list)

        print(f"Generated {len(alert_manager.alerts)} initial alerts")


# ==================== Log Endpoints ====================

@app.get("/api/logs", response_model=SearchResponse)
async def search_logs(
    query: Optional[str] = Query(None, description="Full-text search query"),
    start_time: Optional[str] = Query(None, description="Start time (ISO format)"),
    end_time: Optional[str] = Query(None, description="End time (ISO format)"),
    levels: Optional[str] = Query(None, description="Comma-separated log levels"),
    sources: Optional[str] = Query(None, description="Comma-separated log sources"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    user: Optional[str] = Query(None, description="Filter by user"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Search and filter log entries."""
    start = datetime.now()

    # Parse filters
    level_filters = [LogLevel(l.strip()) for l in levels.split(",")] if levels else None
    source_filters = [LogSource(s.strip()) for s in sources.split(",")] if sources else None

    start_dt = datetime.fromisoformat(start_time) if start_time else None
    end_dt = datetime.fromisoformat(end_time) if end_time else None

    # Filter logs
    results = []
    for log in log_store.values():
        # Time filter
        if start_dt and log.timestamp < start_dt:
            continue
        if end_dt and log.timestamp > end_dt:
            continue

        # Level filter
        if level_filters and log.level not in level_filters:
            continue

        # Source filter
        if source_filters and log.source not in source_filters:
            continue

        # Source IP filter
        if source_ip and log.source_ip != source_ip:
            continue

        # User filter
        if user and log.user != user:
            continue

        # Full-text search
        if query:
            query_lower = query.lower()
            if (query_lower not in log.message.lower() and
                query_lower not in (log.source_ip or "").lower() and
                query_lower not in (log.user or "").lower()):
                continue

        results.append(log)

    # Sort by timestamp descending
    results.sort(key=lambda x: x.timestamp, reverse=True)

    # Apply pagination
    total = len(results)
    paginated = results[offset:offset + limit]

    query_time = (datetime.now() - start).total_seconds() * 1000

    return SearchResponse(
        results=paginated,
        total=total,
        limit=limit,
        offset=offset,
        query_time_ms=query_time
    )


@app.get("/api/logs/{log_id}", response_model=LogEntry)
async def get_log(log_id: str):
    """Get a specific log entry by ID."""
    if log_id not in log_store:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return log_store[log_id]


@app.get("/api/logs/timeline/events")
async def get_timeline_events(
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    user: Optional[str] = Query(None)
):
    """Get timeline events for incident investigation."""
    events = []

    start_dt = datetime.fromisoformat(start_time) if start_time else datetime.now() - timedelta(hours=24)
    end_dt = datetime.fromisoformat(end_time) if end_time else datetime.now()

    # Get relevant logs
    relevant_logs = [
        log for log in log_store.values()
        if start_dt <= log.timestamp <= end_dt
    ]

    # Filter by IP or user if provided
    if source_ip:
        relevant_logs = [log for log in relevant_logs if log.source_ip == source_ip]
    if user:
        relevant_logs = [log for log in relevant_logs if log.user == user]

    # Sort by timestamp
    relevant_logs.sort(key=lambda x: x.timestamp)

    # Create timeline events
    for log in relevant_logs:
        # Determine event severity
        severity = "info"
        if log.level == LogLevel.CRITICAL:
            severity = "critical"
        elif log.level == LogLevel.ERROR:
            severity = "error"
        elif log.level == LogLevel.WARNING:
            severity = "warning"

        event = TimelineEvent(
            timestamp=log.timestamp,
            event_type=f"{log.source.value}_event",
            description=log.message[:200],
            source=log.source.value,
            related_ips=[ip for ip in [log.source_ip, log.dest_ip] if ip],
            related_users=[log.user] if log.user else [],
            severity=severity,
            log_ids=[log.id]
        )
        events.append(event)

    return {"events": events, "total": len(events)}


# ==================== Statistics Endpoints ====================

@app.get("/api/statistics", response_model=LogStatistics)
async def get_statistics():
    """Get log statistics."""
    logs = list(log_store.values())

    if not logs:
        return LogStatistics(
            total_logs=0,
            logs_by_level={},
            logs_by_source={},
            top_source_ips=[],
            top_dest_ips=[],
            error_rate=0.0,
            time_range={"start": "", "end": ""}
        )

    # Count by level
    level_counts = {}
    for level in LogLevel:
        level_counts[level.value] = sum(1 for log in logs if log.level == level)

    # Count by source
    source_counts = {}
    for source in LogSource:
        source_counts[source.value] = sum(1 for log in logs if log.source == source)

    # Top IPs
    from collections import Counter
    source_ip_counter = Counter(log.source_ip for log in logs if log.source_ip)
    dest_ip_counter = Counter(log.dest_ip for log in logs if log.dest_ip)

    error_count = sum(1 for log in logs if log.level in [LogLevel.ERROR, LogLevel.CRITICAL])

    return LogStatistics(
        total_logs=len(logs),
        logs_by_level=level_counts,
        logs_by_source=source_counts,
        top_source_ips=[{"ip": ip, "count": count} for ip, count in source_ip_counter.most_common(10)],
        top_dest_ips=[{"ip": ip, "count": count} for ip, count in dest_ip_counter.most_common(10)],
        error_rate=(error_count / len(logs)) * 100 if logs else 0,
        time_range={
            "start": min(log.timestamp for log in logs).isoformat(),
            "end": max(log.timestamp for log in logs).isoformat()
        }
    )


@app.get("/api/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics():
    """Get dashboard overview metrics."""
    now = datetime.now()
    last_24h = now - timedelta(hours=24)

    # Get logs from last 24 hours
    recent_logs = [log for log in log_store.values() if log.timestamp >= last_24h]

    # Get recent alerts
    recent_alerts = [
        alert for alert in alert_manager.alerts.values()
        if alert.timestamp >= last_24h
    ]

    # Calculate log trend (hourly)
    log_trend = []
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = sum(1 for log in log_store.values() if hour_start <= log.timestamp < hour_end)
        log_trend.append({
            "hour": hour_start.isoformat(),
            "count": count
        })

    # Calculate alert trend
    alert_trend = []
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = sum(1 for alert in alert_manager.alerts.values() if hour_start <= alert.timestamp < hour_end)
        alert_trend.append({
            "hour": hour_start.isoformat(),
            "count": count
        })

    # Top threat sources
    from collections import Counter
    threat_ips = Counter(
        alert.indicators.get("source_ip")
        for alert in recent_alerts
        if alert.indicators.get("source_ip")
    )

    top_threat_sources = [
        {"ip": ip, "alert_count": count}
        for ip, count in threat_ips.most_common(5)
    ]

    # Critical alerts
    critical_count = sum(
        1 for alert in alert_manager.alerts.values()
        if alert.severity == AlertSeverity.CRITICAL and alert.status != "resolved"
    )

    return DashboardMetrics(
        total_logs_24h=len(recent_logs),
        alerts_24h=len(recent_alerts),
        anomalies_24h=0,  # Would track anomalies separately
        critical_alerts=critical_count,
        top_threat_sources=top_threat_sources,
        log_trend=log_trend,
        alert_trend=alert_trend
    )


# ==================== Anomaly Detection Endpoints ====================

@app.post("/api/anomalies/detect")
async def run_anomaly_detection(background_tasks: BackgroundTasks):
    """Trigger anomaly detection on all logs."""
    logs_list = list(log_store.values())

    # Split into baseline and current
    split_time = datetime.now() - timedelta(hours=1)
    baseline_logs = [log for log in logs_list if log.timestamp < split_time]
    current_logs = [log for log in logs_list if log.timestamp >= split_time]

    anomalies = anomaly_detector.detect_anomalies(current_logs, baseline_logs)

    # Generate alerts from anomalies
    new_alerts = alert_manager.process_anomalies(anomalies, logs_list)

    return {
        "anomalies_detected": len(anomalies),
        "alerts_generated": len(new_alerts),
        "anomaly_types": list(set(a.anomaly_type for a in anomalies))
    }


@app.get("/api/anomalies")
async def get_anomalies(
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    min_score: float = Query(0.5, ge=0, le=1),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get detected anomalies."""
    start_dt = datetime.fromisoformat(start_time) if start_time else datetime.now() - timedelta(hours=24)
    end_dt = datetime.fromisoformat(end_time) if end_time else datetime.now()

    # Run anomaly detection
    logs_list = list(log_store.values())
    relevant_logs = [log for log in logs_list if start_dt <= log.timestamp <= end_dt]

    anomalies = anomaly_detector.detect_anomalies(relevant_logs)
    anomalies = [a for a in anomalies if a.score >= min_score]
    anomalies.sort(key=lambda x: x.score, reverse=True)

    return {
        "anomalies": anomalies[:limit],
        "total": len(anomalies)
    }


# ==================== Alert Endpoints ====================

@app.get("/api/alerts")
async def get_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get alerts with optional filtering."""
    severity_filter = AlertSeverity(severity) if severity else None

    alerts = alert_manager.get_alerts(status=status, severity=severity_filter, limit=limit)

    return {
        "alerts": alerts,
        "statistics": alert_manager.get_alert_statistics()
    }


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get a specific alert."""
    alert = alert_manager.alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.put("/api/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    status: str = Query(..., description="New status (new, acknowledged, investigating, resolved)"),
    assigned_to: Optional[str] = Query(None),
    resolution_notes: Optional[str] = Query(None)
):
    """Update alert status."""
    alert = alert_manager.update_alert_status(
        alert_id,
        status,
        assigned_to,
        resolution_notes
    )

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"success": True, "alert": alert}


# ==================== Search and Investigation Endpoints ====================

@app.post("/api/investigate")
async def investigate_incident(
    source_ip: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None)
):
    """
    Deep investigation endpoint that correlates all data related to an incident.
    """
    start_dt = datetime.fromisoformat(start_time) if start_time else datetime.now() - timedelta(hours=24)
    end_dt = datetime.fromisoformat(end_time) if end_time else datetime.now()

    # Get relevant logs
    relevant_logs = []
    for log in log_store.values():
        if not (start_dt <= log.timestamp <= end_dt):
            continue

        if source_ip and log.source_ip != source_ip:
            continue

        if user and log.user != user:
            continue

        relevant_logs.append(log)

    # Get relevant alerts
    relevant_alerts = [
        alert for alert in alert_manager.alerts.values()
        if start_dt <= alert.timestamp <= end_dt and (
            (source_ip and alert.indicators.get("source_ip") == source_ip) or
            (user and alert.indicators.get("user") == user)
        )
    ]

    # Build timeline
    timeline = []
    for log in sorted(relevant_logs, key=lambda x: x.timestamp):
        timeline.append({
            "timestamp": log.timestamp.isoformat(),
            "type": "log",
            "level": log.level.value,
            "source": log.source.value,
            "message": log.message[:150],
            "id": log.id
        })

    for alert in sorted(relevant_alerts, key=lambda x: x.timestamp):
        timeline.append({
            "timestamp": alert.timestamp.isoformat(),
            "type": "alert",
            "severity": alert.severity.value,
            "title": alert.title,
            "id": alert.id
        })

    timeline.sort(key=lambda x: x["timestamp"])

    # Build summary
    from collections import Counter
    source_ips = Counter(log.source_ip for log in relevant_logs if log.source_ip)
    dest_ips = Counter(log.dest_ip for log in relevant_logs if log.dest_ip)
    users = Counter(log.user for log in relevant_logs if log.user)
    ports = Counter(log.dest_port for log in relevant_logs if log.dest_port)

    return {
        "summary": {
            "total_logs": len(relevant_logs),
            "total_alerts": len(relevant_alerts),
            "time_range": {
                "start": start_dt.isoformat(),
                "end": end_dt.isoformat()
            }
        },
        "timeline": timeline,
        "correlated_data": {
            "source_ips": [{"ip": ip, "count": count} for ip, count in source_ips.most_common(10)],
            "destination_ips": [{"ip": ip, "count": count} for ip, count in dest_ips.most_common(10)],
            "users": [{"user": user, "count": count} for user, count in users.most_common(10)],
            "ports": [{"port": port, "count": count} for port, count in ports.most_common(10)]
        },
        "alerts": relevant_alerts,
        "risk_assessment": {
            "risk_level": "high" if len(relevant_alerts) > 5 else "medium" if relevant_alerts else "low",
            "factors": [
                f"{len(relevant_alerts)} related alerts",
                f"{len(relevant_logs)} related log events",
                f"{len(users)} unique users involved"
            ]
        }
    }


# ==================== Frontend Routes ====================

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the main dashboard page."""
    html_path = Path("static/index.html")
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<html><body><h1>Dashboard not found</h1></body></html>")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "logs_count": len(log_store),
        "alerts_count": len(alert_manager.alerts),
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
