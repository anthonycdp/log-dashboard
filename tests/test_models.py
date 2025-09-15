"""
Unit tests for data models in the Security Log Dashboard.
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from models import (
    LogEntry, Alert, AnomalyResult, LogLevel, LogSource, AlertSeverity,
    SearchQuery, SearchResponse, LogStatistics, DashboardMetrics, TimelineEvent
)


class TestLogLevel:
    """Tests for LogLevel enum."""

    def test_log_level_values(self):
        """Test that all log levels have expected string values."""
        assert LogLevel.DEBUG.value == "DEBUG"
        assert LogLevel.INFO.value == "INFO"
        assert LogLevel.WARNING.value == "WARNING"
        assert LogLevel.ERROR.value == "ERROR"
        assert LogLevel.CRITICAL.value == "CRITICAL"

    def test_log_level_from_string(self):
        """Test creating LogLevel from string value."""
        assert LogLevel("DEBUG") == LogLevel.DEBUG
        assert LogLevel("ERROR") == LogLevel.ERROR


class TestLogSource:
    """Tests for LogSource enum."""

    def test_log_source_values(self):
        """Test that all log sources have expected string values."""
        assert LogSource.FIREWALL.value == "firewall"
        assert LogSource.IDS.value == "ids"
        assert LogSource.AUTH.value == "authentication"
        assert LogSource.WEB_SERVER.value == "web_server"
        assert LogSource.DATABASE.value == "database"
        assert LogSource.SYSTEM.value == "system"
        assert LogSource.APPLICATION.value == "application"


class TestAlertSeverity:
    """Tests for AlertSeverity enum."""

    def test_alert_severity_values(self):
        """Test that all alert severities have expected string values."""
        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.CRITICAL.value == "critical"


class TestLogEntry:
    """Tests for LogEntry model."""

    def test_create_minimal_log_entry(self):
        """Test creating a log entry with only required fields."""
        entry = LogEntry(
            id="test-001",
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            source=LogSource.SYSTEM,
            message="Test message"
        )
        assert entry.id == "test-001"
        assert entry.level == LogLevel.INFO
        assert entry.source == LogSource.SYSTEM
        assert entry.message == "Test message"
        assert entry.tags == []
        assert entry.metadata == {}

    def test_create_full_log_entry(self, sample_log_entry):
        """Test creating a log entry with all fields."""
        assert sample_log_entry.source_ip == "192.168.1.100"
        assert sample_log_entry.dest_ip == "10.0.0.1"
        assert sample_log_entry.source_port == 54321
        assert sample_log_entry.dest_port == 443
        assert sample_log_entry.protocol == "HTTPS"
        assert sample_log_entry.user == "admin"
        assert sample_log_entry.hostname == "server01"
        assert sample_log_entry.process == "sshd"
        assert "authentication" in sample_log_entry.tags

    def test_log_entry_missing_required_field(self):
        """Test that missing required fields raise ValidationError."""
        with pytest.raises(ValidationError):
            LogEntry(id="test-001")

        with pytest.raises(ValidationError):
            LogEntry(id="test-001", timestamp=datetime.now())

    def test_log_entry_json_serialization(self, sample_log_entry):
        """Test JSON serialization of LogEntry."""
        json_data = sample_log_entry.model_dump()
        assert "id" in json_data
        assert "timestamp" in json_data
        assert "level" in json_data

    def test_log_entry_with_optional_fields_none(self):
        """Test log entry with optional fields set to None."""
        entry = LogEntry(
            id="test-002",
            timestamp=datetime.now(),
            level=LogLevel.ERROR,
            source=LogSource.DATABASE,
            message="Error message",
            source_ip=None,
            dest_ip=None,
            user=None
        )
        assert entry.source_ip is None
        assert entry.dest_ip is None
        assert entry.user is None


class TestAlert:
    """Tests for Alert model."""

    def test_create_alert(self, sample_alert):
        """Test creating an alert."""
        assert sample_alert.id == "alert-001"
        assert sample_alert.severity == AlertSeverity.HIGH
        assert sample_alert.status == "new"
        assert len(sample_alert.related_logs) == 2

    def test_alert_default_values(self):
        """Test alert default values."""
        alert = Alert(
            id="alert-002",
            timestamp=datetime.now(),
            severity=AlertSeverity.MEDIUM,
            title="Test Alert",
            description="Test description",
            source="test"
        )
        assert alert.status == "new"
        assert alert.related_logs == []
        assert alert.indicators == {}

    def test_alert_missing_required_field(self):
        """Test that missing required fields raise ValidationError."""
        with pytest.raises(ValidationError):
            Alert(id="alert-001", timestamp=datetime.now())


class TestAnomalyResult:
    """Tests for AnomalyResult model."""

    def test_create_anomaly_result(self, sample_anomaly_result):
        """Test creating an anomaly result."""
        assert sample_anomaly_result.log_id == "log-001"
        assert sample_anomaly_result.anomaly_type == "log_rate_spike"
        assert sample_anomaly_result.score == 0.85
        assert sample_anomaly_result.baseline_value == 100.0
        assert sample_anomaly_result.observed_value == 500.0

    def test_anomaly_score_validation_valid(self):
        """Test that valid scores are accepted."""
        for score in [0.0, 0.5, 1.0]:
            result = AnomalyResult(
                log_id="test",
                timestamp=datetime.now(),
                anomaly_type="test",
                score=score,
                description="Test",
                baseline_value=0.0,
                observed_value=1.0
            )
            assert result.score == score

    def test_anomaly_score_validation_invalid(self):
        """Test that invalid scores raise ValidationError."""
        with pytest.raises(ValidationError):
            AnomalyResult(
                log_id="test",
                timestamp=datetime.now(),
                anomaly_type="test",
                score=1.5,  # Invalid: > 1.0
                description="Test",
                baseline_value=0.0,
                observed_value=1.0
            )

        with pytest.raises(ValidationError):
            AnomalyResult(
                log_id="test",
                timestamp=datetime.now(),
                anomaly_type="test",
                score=-0.5,  # Invalid: < 0.0
                description="Test",
                baseline_value=0.0,
                observed_value=1.0
            )


class TestSearchQuery:
    """Tests for SearchQuery model."""

    def test_create_search_query_defaults(self):
        """Test creating a search query with default values."""
        query = SearchQuery()
        assert query.limit == 100
        assert query.offset == 0
        assert query.query is None

    def test_create_search_query_with_filters(self):
        """Test creating a search query with filters."""
        query = SearchQuery(
            query="error",
            levels=[LogLevel.ERROR, LogLevel.CRITICAL],
            sources=[LogSource.DATABASE],
            limit=50
        )
        assert query.query == "error"
        assert len(query.levels) == 2
        assert len(query.sources) == 1
        assert query.limit == 50

    def test_search_query_limit_validation(self):
        """Test that limit boundaries are enforced."""
        # Valid limits
        SearchQuery(limit=1)
        SearchQuery(limit=10000)

        # Invalid limits
        with pytest.raises(ValidationError):
            SearchQuery(limit=0)

        with pytest.raises(ValidationError):
            SearchQuery(limit=10001)


class TestSearchResponse:
    """Tests for SearchResponse model."""

    def test_create_search_response(self):
        """Test creating a search response."""
        response = SearchResponse(
            results=[],
            total=0,
            limit=100,
            offset=0,
            query_time_ms=15.5
        )
        assert response.results == []
        assert response.total == 0
        assert response.query_time_ms == 15.5


class TestLogStatistics:
    """Tests for LogStatistics model."""

    def test_create_log_statistics(self):
        """Test creating log statistics."""
        stats = LogStatistics(
            total_logs=1000,
            logs_by_level={"ERROR": 50, "INFO": 900},
            logs_by_source={"system": 800, "auth": 200},
            top_source_ips=[{"ip": "10.0.0.1", "count": 500}],
            top_dest_ips=[{"ip": "10.0.0.2", "count": 300}],
            error_rate=5.0,
            time_range={"start": "2024-01-01", "end": "2024-01-02"}
        )
        assert stats.total_logs == 1000
        assert stats.error_rate == 5.0


class TestDashboardMetrics:
    """Tests for DashboardMetrics model."""

    def test_create_dashboard_metrics(self):
        """Test creating dashboard metrics."""
        metrics = DashboardMetrics(
            total_logs_24h=5000,
            alerts_24h=25,
            anomalies_24h=10,
            critical_alerts=3,
            top_threat_sources=[{"ip": "10.0.0.1", "alert_count": 5}],
            log_trend=[],
            alert_trend=[]
        )
        assert metrics.total_logs_24h == 5000
        assert metrics.alerts_24h == 25
        assert metrics.critical_alerts == 3


class TestTimelineEvent:
    """Tests for TimelineEvent model."""

    def test_create_timeline_event(self):
        """Test creating a timeline event."""
        event = TimelineEvent(
            timestamp=datetime.now(),
            event_type="auth_event",
            description="User logged in",
            source="authentication",
            related_ips=["192.168.1.1"],
            related_users=["admin"],
            severity="info",
            log_ids=["log-001"]
        )
        assert event.event_type == "auth_event"
        assert len(event.related_ips) == 1
        assert len(event.related_users) == 1

    def test_timeline_event_defaults(self):
        """Test timeline event default values."""
        event = TimelineEvent(
            timestamp=datetime.now(),
            event_type="test",
            description="Test event",
            source="test"
        )
        assert event.related_ips == []
        assert event.related_users == []
        assert event.severity == "info"
        assert event.log_ids == []
