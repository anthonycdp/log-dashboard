"""
Unit tests for FastAPI endpoints in the Security Log Dashboard.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch
import sys
import os

# Need to set up proper imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="module")
def app():
    """Create test app with mocked data loading."""
    # Patch load_sample_data to avoid loading real data during tests
    with patch('main.load_sample_data'):
        from main import app as fastapi_app
        yield fastapi_app


@pytest.fixture
def client(app):
    """Create a test client for the FastAPI app."""
    from starlette.testclient import TestClient
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def clean_state():
    """Clear global state before each test."""
    from main import log_store, alert_manager
    log_store.clear()
    alert_manager.alerts.clear()
    yield
    log_store.clear()
    alert_manager.alerts.clear()


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check_returns_healthy(self, client):
        """Test that health endpoint returns healthy status."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestLogEndpoints:
    """Tests for log-related endpoints."""

    def test_search_logs_empty(self, client, clean_state):
        """Test searching logs when none exist."""
        response = client.get("/api/logs")

        assert response.status_code == 200
        data = response.json()
        assert data["results"] == []
        assert data["total"] == 0

    def test_search_logs_with_data(self, client, clean_state):
        """Test searching logs with existing data."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add a log entry
        log = LogEntry(
            id="test-log-1",
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            source=LogSource.SYSTEM,
            message="Test log entry"
        )
        log_store[log.id] = log

        response = client.get("/api/logs")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["results"]) == 1
        assert data["results"][0]["id"] == "test-log-1"

    def test_search_logs_with_query(self, client, clean_state):
        """Test full-text search in logs."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs with different content
        log1 = LogEntry(
            id="log-1",
            timestamp=datetime.now(),
            level=LogLevel.ERROR,
            source=LogSource.SYSTEM,
            message="Database connection error"
        )
        log2 = LogEntry(
            id="log-2",
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            source=LogSource.SYSTEM,
            message="Normal system log"
        )
        log_store[log1.id] = log1
        log_store[log2.id] = log2

        response = client.get("/api/logs?query=error")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert "error" in data["results"][0]["message"].lower()

    def test_search_logs_with_level_filter(self, client, clean_state):
        """Test filtering logs by level."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs with different levels
        for i, level in enumerate([LogLevel.DEBUG, LogLevel.INFO, LogLevel.ERROR, LogLevel.CRITICAL]):
            log = LogEntry(
                id=f"log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=level,
                source=LogSource.SYSTEM,
                message=f"Log with level {level.value}"
            )
            log_store[log.id] = log

        response = client.get("/api/logs?levels=ERROR,CRITICAL")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2

    def test_search_logs_with_source_filter(self, client, clean_state):
        """Test filtering logs by source."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs from different sources
        for i, source in enumerate([LogSource.SYSTEM, LogSource.AUTH, LogSource.DATABASE]):
            log = LogEntry(
                id=f"log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=source,
                message=f"Log from {source.value}"
            )
            log_store[log.id] = log

        response = client.get("/api/logs?sources=authentication")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["results"][0]["source"] == "authentication"

    def test_search_logs_pagination(self, client, clean_state):
        """Test log pagination."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add 25 logs
        for i in range(25):
            log = LogEntry(
                id=f"log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message=f"Log entry {i}"
            )
            log_store[log.id] = log

        # Test first page
        response = client.get("/api/logs?limit=10&offset=0")
        data = response.json()
        assert data["total"] == 25
        assert len(data["results"]) == 10

        # Test second page
        response = client.get("/api/logs?limit=10&offset=10")
        data = response.json()
        assert len(data["results"]) == 10

        # Test last page
        response = client.get("/api/logs?limit=10&offset=20")
        data = response.json()
        assert len(data["results"]) == 5

    def test_get_log_by_id(self, client, clean_state):
        """Test getting a specific log by ID."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        log = LogEntry(
            id="specific-log",
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            source=LogSource.SYSTEM,
            message="Specific log entry"
        )
        log_store[log.id] = log

        response = client.get("/api/logs/specific-log")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "specific-log"

    def test_get_log_by_id_not_found(self, client, clean_state):
        """Test getting a non-existent log."""
        response = client.get("/api/logs/nonexistent-id")

        assert response.status_code == 404


class TestStatisticsEndpoints:
    """Tests for statistics endpoints."""

    def test_get_statistics_empty(self, client, clean_state):
        """Test statistics when no logs exist."""
        response = client.get("/api/statistics")

        assert response.status_code == 200
        data = response.json()
        assert data["total_logs"] == 0
        assert data["error_rate"] == 0.0

    def test_get_statistics_with_logs(self, client, clean_state):
        """Test statistics with log data."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs with different levels
        for i in range(90):
            log = LogEntry(
                id=f"info-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Info log",
                source_ip="10.0.0.1"
            )
            log_store[log.id] = log

        for i in range(10):
            log = LogEntry(
                id=f"error-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.ERROR,
                source=LogSource.APPLICATION,
                message="Error log",
                source_ip="10.0.0.2"
            )
            log_store[log.id] = log

        response = client.get("/api/statistics")

        assert response.status_code == 200
        data = response.json()
        assert data["total_logs"] == 100
        assert data["error_rate"] == 10.0  # 10 errors out of 100
        assert len(data["top_source_ips"]) > 0

    def test_get_dashboard_metrics(self, client, clean_state):
        """Test dashboard metrics endpoint."""
        response = client.get("/api/dashboard/metrics")

        assert response.status_code == 200
        data = response.json()
        assert "total_logs_24h" in data
        assert "alerts_24h" in data
        assert "critical_alerts" in data
        assert "log_trend" in data
        assert "alert_trend" in data


class TestAlertEndpoints:
    """Tests for alert-related endpoints."""

    def test_get_alerts_empty(self, client, clean_state):
        """Test getting alerts when none exist."""
        response = client.get("/api/alerts")

        assert response.status_code == 200
        data = response.json()
        assert data["alerts"] == []
        assert data["statistics"]["total"] == 0

    def test_get_alerts_with_data(self, client, clean_state):
        """Test getting alerts with existing data."""
        from main import alert_manager
        from models import Alert, AlertSeverity

        # Add an alert
        alert = Alert(
            id="alert-001",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            description="Test alert description",
            source="test"
        )
        alert_manager.alerts[alert.id] = alert

        response = client.get("/api/alerts")

        assert response.status_code == 200
        data = response.json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["id"] == "alert-001"

    def test_get_alerts_filter_by_status(self, client, clean_state):
        """Test filtering alerts by status."""
        from main import alert_manager
        from models import Alert, AlertSeverity

        # Add alerts with different statuses
        for i, status in enumerate(["new", "acknowledged", "resolved"]):
            alert = Alert(
                id=f"alert-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                severity=AlertSeverity.MEDIUM,
                title=f"Alert {i}",
                description="Test",
                source="test",
                status=status
            )
            alert_manager.alerts[alert.id] = alert

        response = client.get("/api/alerts?status=new")

        assert response.status_code == 200
        data = response.json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["status"] == "new"

    def test_get_alerts_filter_by_severity(self, client, clean_state):
        """Test filtering alerts by severity."""
        from main import alert_manager
        from models import Alert, AlertSeverity

        # Add alerts with different severities
        for i, severity in enumerate([AlertSeverity.LOW, AlertSeverity.HIGH, AlertSeverity.CRITICAL]):
            alert = Alert(
                id=f"alert-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                severity=severity,
                title=f"Alert {i}",
                description="Test",
                source="test"
            )
            alert_manager.alerts[alert.id] = alert

        response = client.get("/api/alerts?severity=critical")

        assert response.status_code == 200
        data = response.json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["severity"] == "critical"

    def test_get_alert_by_id(self, client, clean_state):
        """Test getting a specific alert."""
        from main import alert_manager
        from models import Alert, AlertSeverity

        alert = Alert(
            id="specific-alert",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Specific Alert",
            description="Test",
            source="test"
        )
        alert_manager.alerts[alert.id] = alert

        response = client.get("/api/alerts/specific-alert")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "specific-alert"

    def test_get_alert_by_id_not_found(self, client, clean_state):
        """Test getting a non-existent alert."""
        response = client.get("/api/alerts/nonexistent-id")

        assert response.status_code == 404

    def test_update_alert_status(self, client, clean_state):
        """Test updating alert status."""
        from main import alert_manager
        from models import Alert, AlertSeverity

        alert = Alert(
            id="alert-to-update",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Alert to Update",
            description="Test",
            source="test"
        )
        alert_manager.alerts[alert.id] = alert

        response = client.put(
            "/api/alerts/alert-to-update/status",
            params={"status": "acknowledged", "assigned_to": "analyst1"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["alert"]["status"] == "acknowledged"
        assert data["alert"]["assigned_to"] == "analyst1"

    def test_update_alert_status_not_found(self, client, clean_state):
        """Test updating status of non-existent alert."""
        response = client.put(
            "/api/alerts/nonexistent/status",
            params={"status": "resolved"}
        )

        assert response.status_code == 404


class TestAnomalyEndpoints:
    """Tests for anomaly detection endpoints."""

    def test_run_anomaly_detection(self, client, clean_state):
        """Test triggering anomaly detection."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add some logs
        for i in range(20):
            log = LogEntry(
                id=f"anomaly-log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Test log"
            )
            log_store[log.id] = log

        response = client.post("/api/anomalies/detect")

        assert response.status_code == 200
        data = response.json()
        assert "anomalies_detected" in data
        assert "alerts_generated" in data
        assert "anomaly_types" in data

    def test_get_anomalies(self, client, clean_state):
        """Test getting detected anomalies."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add some logs for anomaly detection
        for i in range(30):
            log = LogEntry(
                id=f"test-log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Test log"
            )
            log_store[log.id] = log

        response = client.get("/api/anomalies")

        assert response.status_code == 200
        data = response.json()
        assert "anomalies" in data
        assert "total" in data

    def test_get_anomalies_with_min_score(self, client, clean_state):
        """Test getting anomalies with minimum score filter."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs
        for i in range(30):
            log = LogEntry(
                id=f"score-log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Test log"
            )
            log_store[log.id] = log

        response = client.get("/api/anomalies?min_score=0.8")

        assert response.status_code == 200
        data = response.json()
        # All returned anomalies should have score >= 0.8
        for anomaly in data["anomalies"]:
            assert anomaly["score"] >= 0.8


class TestTimelineEndpoint:
    """Tests for timeline endpoint."""

    def test_get_timeline_events_empty(self, client, clean_state):
        """Test timeline with no logs."""
        response = client.get("/api/logs/timeline/events")

        assert response.status_code == 200
        data = response.json()
        assert data["events"] == []
        assert data["total"] == 0

    def test_get_timeline_events_with_data(self, client, clean_state):
        """Test timeline with log data."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs at different times
        for i in range(10):
            log = LogEntry(
                id=f"timeline-log-{i}",
                timestamp=datetime.now() - timedelta(hours=i),
                level=LogLevel.INFO if i % 2 == 0 else LogLevel.ERROR,
                source=LogSource.AUTH,
                message=f"Timeline event {i}",
                source_ip="192.168.1.1",
                user="admin"
            )
            log_store[log.id] = log

        response = client.get("/api/logs/timeline/events")

        assert response.status_code == 200
        data = response.json()
        assert len(data["events"]) > 0
        assert "timestamp" in data["events"][0]
        assert "event_type" in data["events"][0]

    def test_get_timeline_events_filter_by_ip(self, client, clean_state):
        """Test filtering timeline by source IP."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs from different IPs
        for i in range(5):
            log = LogEntry(
                id=f"ip-log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message=f"Log from IP {i}",
                source_ip=f"192.168.1.{i}"
            )
            log_store[log.id] = log

        response = client.get("/api/logs/timeline/events?source_ip=192.168.1.2")

        assert response.status_code == 200
        data = response.json()
        for event in data["events"]:
            assert "192.168.1.2" in event.get("related_ips", [])

    def test_get_timeline_events_filter_by_user(self, client, clean_state):
        """Test filtering timeline by user."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs from different users
        for i, user in enumerate(["admin", "guest", "admin", "system"]):
            log = LogEntry(
                id=f"user-log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.AUTH,
                message=f"Log by {user}",
                user=user
            )
            log_store[log.id] = log

        response = client.get("/api/logs/timeline/events?user=admin")

        assert response.status_code == 200
        data = response.json()
        for event in data["events"]:
            assert "admin" in event.get("related_users", [])


class TestInvestigateEndpoint:
    """Tests for investigation endpoint."""

    def test_investigate_incident_empty(self, client, clean_state):
        """Test investigation with no data."""
        response = client.post("/api/investigate")

        assert response.status_code == 200
        data = response.json()
        assert data["summary"]["total_logs"] == 0
        assert data["summary"]["total_alerts"] == 0

    def test_investigate_incident_by_ip(self, client, clean_state):
        """Test investigation filtered by IP."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs from different IPs
        for i in range(10):
            log = LogEntry(
                id=f"inv-log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.WARNING if i < 3 else LogLevel.INFO,
                source=LogSource.AUTH,
                message=f"Investigation log {i}",
                source_ip="10.0.0.1" if i < 5 else "10.0.0.2",
                user="admin" if i < 3 else "guest"
            )
            log_store[log.id] = log

        response = client.post("/api/investigate?source_ip=10.0.0.1")

        assert response.status_code == 200
        data = response.json()
        assert data["summary"]["total_logs"] == 5
        assert "timeline" in data
        assert "correlated_data" in data
        assert "risk_assessment" in data

    def test_investigate_incident_by_user(self, client, clean_state):
        """Test investigation filtered by user."""
        from main import log_store
        from models import LogEntry, LogLevel, LogSource

        # Add logs for different users
        for i in range(10):
            log = LogEntry(
                id=f"inv-user-log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.AUTH,
                message=f"User activity log {i}",
                source_ip="10.0.0.1",
                user="suspicious_user" if i < 5 else "normal_user"
            )
            log_store[log.id] = log

        response = client.post("/api/investigate?user=suspicious_user")

        assert response.status_code == 200
        data = response.json()
        assert data["summary"]["total_logs"] == 5

    def test_investigate_risk_assessment(self, client, clean_state):
        """Test risk assessment in investigation."""
        from main import log_store, alert_manager
        from models import LogEntry, LogLevel, LogSource, Alert, AlertSeverity

        # Add logs and alerts
        for i in range(20):
            log = LogEntry(
                id=f"risk-log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.WARNING,
                source=LogSource.AUTH,
                message="Risk assessment log",
                source_ip="10.0.0.50",
                user="test"
            )
            log_store[log.id] = log

        # Add some alerts
        for i in range(3):
            alert = Alert(
                id=f"risk-alert-{i}",
                timestamp=datetime.now() - timedelta(minutes=i * 5),
                severity=AlertSeverity.HIGH,
                title=f"Risk Alert {i}",
                description="Test alert",
                source="test",
                indicators={"source_ip": "10.0.0.50", "user": "test"}
            )
            alert_manager.alerts[alert.id] = alert

        response = client.post("/api/investigate?source_ip=10.0.0.50")

        assert response.status_code == 200
        data = response.json()
        assert "risk_assessment" in data
        assert "risk_level" in data["risk_assessment"]
        assert "factors" in data["risk_assessment"]


class TestDashboardEndpoint:
    """Tests for the main dashboard endpoint."""

    def test_dashboard_page(self, client):
        """Test that dashboard endpoint returns HTML."""
        response = client.get("/")

        assert response.status_code == 200
        # Should return HTML content
        assert "text/html" in response.headers.get("content-type", "")
