"""
Unit tests for alert manager module in the Security Log Dashboard.
"""

import pytest
from datetime import datetime, timedelta

from alert_manager import AlertManager, AlertRule
from models import LogEntry, Alert, AnomalyResult, LogLevel, LogSource, AlertSeverity


class TestAlertRule:
    """Tests for AlertRule class."""

    def test_rule_initialization(self):
        """Test alert rule initialization."""
        rule = AlertRule(
            name="test_rule",
            severity=AlertSeverity.HIGH,
            description="Test rule description",
            cooldown_minutes=30
        )

        assert rule.name == "test_rule"
        assert rule.severity == AlertSeverity.HIGH
        assert rule.description == "Test rule description"
        assert rule.cooldown == timedelta(minutes=30)
        assert rule.last_triggered == {}

    def test_rule_should_trigger_first_time(self):
        """Test that rule triggers for the first time."""
        rule = AlertRule(
            name="test_rule",
            severity=AlertSeverity.MEDIUM,
            description="Test",
            cooldown_minutes=60
        )

        assert rule.should_trigger("192.168.1.1") is True

    def test_rule_should_trigger_respects_cooldown(self):
        """Test that rule respects cooldown period."""
        rule = AlertRule(
            name="test_rule",
            severity=AlertSeverity.MEDIUM,
            description="Test",
            cooldown_minutes=60
        )

        # Trigger the rule
        rule.mark_triggered("192.168.1.1")

        # Should not trigger again immediately
        assert rule.should_trigger("192.168.1.1") is False

        # Different key should still trigger
        assert rule.should_trigger("192.168.1.2") is True

    def test_rule_should_trigger_after_cooldown(self):
        """Test that rule triggers after cooldown expires."""
        rule = AlertRule(
            name="test_rule",
            severity=AlertSeverity.MEDIUM,
            description="Test",
            cooldown_minutes=60
        )

        # Simulate triggering 2 hours ago
        rule.last_triggered["192.168.1.1"] = datetime.now() - timedelta(hours=2)

        # Should trigger now that cooldown has passed
        assert rule.should_trigger("192.168.1.1") is True

    def test_rule_zero_cooldown(self):
        """Test rule with zero cooldown (always triggers)."""
        rule = AlertRule(
            name="instant_rule",
            severity=AlertSeverity.CRITICAL,
            description="Always triggers",
            cooldown_minutes=0
        )

        rule.mark_triggered("10.0.0.1")

        # Should still trigger even after being marked
        assert rule.should_trigger("10.0.0.1") is True


class TestAlertManager:
    """Tests for AlertManager class."""

    def test_manager_initialization(self):
        """Test alert manager initialization."""
        manager = AlertManager()

        assert manager.alerts == {}
        assert len(manager.alert_rules) > 0
        assert manager.correlation_window == timedelta(minutes=30)

    def test_manager_has_required_rules(self):
        """Test that manager has all required default rules."""
        manager = AlertManager()
        rule_names = [rule.name for rule in manager.alert_rules]

        required_rules = [
            "multiple_failed_logins",
            "brute_force_detected",
            "port_scan_detected",
            "sql_injection_attempt",
            "unauthorized_access",
            "malware_signature",
            "ddos_attack",
            "data_exfiltration",
            "privilege_escalation",
            "anomalous_activity"
        ]

        for rule_name in required_rules:
            assert rule_name in rule_names

    def test_process_logs_empty(self):
        """Test processing empty log list."""
        manager = AlertManager()
        alerts = manager.process_logs([])

        assert alerts == []

    def test_process_logs_normal_logs(self):
        """Test processing normal logs (no alerts)."""
        manager = AlertManager()

        logs = [
            LogEntry(
                id=f"normal-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Normal system log entry",
                source_ip="192.168.1.1"
            )
            for i in range(10)
        ]

        alerts = manager.process_logs(logs)

        # Normal logs should not generate alerts
        assert len(alerts) == 0

    def test_detect_multiple_failed_logins(self, sample_failed_login_logs):
        """Test detection of multiple failed login attempts."""
        manager = AlertManager()

        alerts = manager.process_logs(sample_failed_login_logs)

        assert len(alerts) > 0
        login_alert = next(
            (a for a in alerts if "Failed Login" in a.title),
            None
        )
        assert login_alert is not None
        assert login_alert.severity in [AlertSeverity.MEDIUM, AlertSeverity.HIGH]

    def test_detect_sql_injection(self, sample_sql_injection_log):
        """Test detection of SQL injection attempts."""
        manager = AlertManager()

        alerts = manager.process_logs([sample_sql_injection_log])

        assert len(alerts) > 0
        sql_alert = next(
            (a for a in alerts if "SQL Injection" in a.title),
            None
        )
        assert sql_alert is not None
        assert sql_alert.severity == AlertSeverity.HIGH
        assert "10.0.0.100" in sql_alert.description

    def test_detect_port_scan(self, sample_port_scan_logs):
        """Test detection of port scanning activity."""
        manager = AlertManager()

        alerts = manager.process_logs(sample_port_scan_logs)

        assert len(alerts) > 0
        port_scan_alert = next(
            (a for a in alerts if "Port Scan" in a.title),
            None
        )
        assert port_scan_alert is not None
        assert "192.168.100.50" in port_scan_alert.description

    def test_detect_ddos_attack(self, ddos_attack_logs):
        """Test detection of DDoS attack patterns."""
        manager = AlertManager()

        alerts = manager.process_logs(ddos_attack_logs)

        # DDoS requires high volume from many IPs
        ddos_alert = next(
            (a for a in alerts if "DDoS" in a.title),
            None
        )
        assert ddos_alert is not None
        assert ddos_alert.severity == AlertSeverity.CRITICAL

    def test_detect_malware_signature(self):
        """Test detection of malware signatures."""
        manager = AlertManager()

        log = LogEntry(
            id="malware-001",
            timestamp=datetime.now(),
            level=LogLevel.CRITICAL,
            source=LogSource.IDS,
            message="Malware signature detected: Trojan.GenericKD.46587432",
            source_ip="10.0.0.50",
            hostname="workstation-05"
        )

        alerts = manager.process_logs([log])

        malware_alert = next(
            (a for a in alerts if "Malware" in a.title),
            None
        )
        assert malware_alert is not None
        assert malware_alert.severity == AlertSeverity.CRITICAL

    def test_detect_unauthorized_access(self):
        """Test detection of unauthorized access attempts."""
        manager = AlertManager()

        log = LogEntry(
            id="unauth-001",
            timestamp=datetime.now(),
            level=LogLevel.WARNING,
            source=LogSource.AUTH,
            message="Unauthorized access attempt to restricted resource",
            source_ip="192.168.1.100",
            user="guest",
            metadata={"resource": "/admin/config", "action": "read"}
        )

        alerts = manager.process_logs([log])

        unauth_alert = next(
            (a for a in alerts if "Unauthorized" in a.title),
            None
        )
        assert unauth_alert is not None
        assert unauth_alert.severity == AlertSeverity.HIGH


class TestAlertManagerAnomalyProcessing:
    """Tests for alert manager anomaly processing."""

    def test_process_anomalies_empty(self):
        """Test processing empty anomaly list."""
        manager = AlertManager()
        alerts = manager.process_anomalies([], [])

        assert alerts == []

    def test_process_anomalies_high_score(self, sample_anomaly_result, sample_log_entry):
        """Test processing high-confidence anomalies."""
        manager = AlertManager()

        # Anomaly with score 0.85 should generate alert (threshold is 0.7)
        anomaly = AnomalyResult(
            log_id=sample_log_entry.id,
            timestamp=datetime.now(),
            anomaly_type="test_anomaly",
            score=0.85,
            description="High confidence anomaly",
            baseline_value=10.0,
            observed_value=50.0
        )

        alerts = manager.process_anomalies([anomaly], [sample_log_entry])

        assert len(alerts) == 1
        assert "Anomaly Detected" in alerts[0].title

    def test_process_anomalies_low_score(self, sample_log_entry):
        """Test that low-confidence anomalies don't generate alerts."""
        manager = AlertManager()

        # Anomaly with score 0.5 should NOT generate alert (threshold is 0.7)
        anomaly = AnomalyResult(
            log_id=sample_log_entry.id,
            timestamp=datetime.now(),
            anomaly_type="test_anomaly",
            score=0.5,
            description="Low confidence anomaly",
            baseline_value=10.0,
            observed_value=15.0
        )

        alerts = manager.process_anomalies([anomaly], [sample_log_entry])

        assert len(alerts) == 0

    def test_process_anomalies_severity_mapping(self, sample_log_entry):
        """Test anomaly score to alert severity mapping."""
        manager = AlertManager()

        test_cases = [
            (0.95, AlertSeverity.CRITICAL),
            (0.85, AlertSeverity.HIGH),
            (0.75, AlertSeverity.MEDIUM),
            (0.70, AlertSeverity.MEDIUM),
        ]

        for score, expected_severity in test_cases:
            manager.alerts = {}  # Reset

            anomaly = AnomalyResult(
                log_id=sample_log_entry.id,
                timestamp=datetime.now(),
                anomaly_type="test",
                score=score,
                description="Test",
                baseline_value=0,
                observed_value=1
            )

            alerts = manager.process_anomalies([anomaly], [sample_log_entry])

            assert len(alerts) == 1
            assert alerts[0].severity == expected_severity


class TestAlertManagerAlertRetrieval:
    """Tests for alert retrieval and filtering."""

    def test_get_alerts_empty(self):
        """Test getting alerts when none exist."""
        manager = AlertManager()
        alerts = manager.get_alerts()

        assert alerts == []

    def test_get_alerts_all(self, sample_alert):
        """Test getting all alerts."""
        manager = AlertManager()
        manager.alerts[sample_alert.id] = sample_alert

        alerts = manager.get_alerts()

        assert len(alerts) == 1
        assert alerts[0].id == sample_alert.id

    def test_get_alerts_filter_by_status(self):
        """Test filtering alerts by status."""
        manager = AlertManager()

        # Create alerts with different statuses
        for i, status in enumerate(["new", "acknowledged", "resolved"]):
            alert = Alert(
                id=f"alert-{i}",
                timestamp=datetime.now(),
                severity=AlertSeverity.MEDIUM,
                title=f"Alert {i}",
                description="Test",
                source="test",
                status=status
            )
            manager.alerts[alert.id] = alert

        new_alerts = manager.get_alerts(status="new")
        assert len(new_alerts) == 1
        assert new_alerts[0].status == "new"

    def test_get_alerts_filter_by_severity(self):
        """Test filtering alerts by severity."""
        manager = AlertManager()

        # Create alerts with different severities
        for i, severity in enumerate([AlertSeverity.LOW, AlertSeverity.HIGH, AlertSeverity.CRITICAL]):
            alert = Alert(
                id=f"alert-{i}",
                timestamp=datetime.now(),
                severity=severity,
                title=f"Alert {i}",
                description="Test",
                source="test"
            )
            manager.alerts[alert.id] = alert

        critical_alerts = manager.get_alerts(severity=AlertSeverity.CRITICAL)
        assert len(critical_alerts) == 1
        assert critical_alerts[0].severity == AlertSeverity.CRITICAL

    def test_get_alerts_limit(self):
        """Test alert retrieval limit."""
        manager = AlertManager()

        # Create 20 alerts
        for i in range(20):
            alert = Alert(
                id=f"alert-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                severity=AlertSeverity.MEDIUM,
                title=f"Alert {i}",
                description="Test",
                source="test"
            )
            manager.alerts[alert.id] = alert

        alerts = manager.get_alerts(limit=5)
        assert len(alerts) == 5

    def test_get_alerts_sorted_by_timestamp(self):
        """Test that alerts are sorted by timestamp descending."""
        manager = AlertManager()

        # Create alerts with different timestamps
        for i in range(5):
            alert = Alert(
                id=f"alert-{i}",
                timestamp=datetime.now() - timedelta(hours=i),
                severity=AlertSeverity.MEDIUM,
                title=f"Alert {i}",
                description="Test",
                source="test"
            )
            manager.alerts[alert.id] = alert

        alerts = manager.get_alerts()

        # Verify descending order
        for i in range(len(alerts) - 1):
            assert alerts[i].timestamp >= alerts[i + 1].timestamp


class TestAlertManagerStatusUpdate:
    """Tests for alert status updates."""

    def test_update_alert_status(self, sample_alert):
        """Test updating alert status."""
        manager = AlertManager()
        manager.alerts[sample_alert.id] = sample_alert

        updated = manager.update_alert_status(
            sample_alert.id,
            "acknowledged",
            assigned_to="analyst1"
        )

        assert updated is not None
        assert updated.status == "acknowledged"
        assert updated.assigned_to == "analyst1"

    def test_update_alert_status_resolved(self, sample_alert):
        """Test resolving an alert."""
        manager = AlertManager()
        manager.alerts[sample_alert.id] = sample_alert

        updated = manager.update_alert_status(
            sample_alert.id,
            "resolved",
            resolution_notes="False positive - legitimate admin activity"
        )

        assert updated is not None
        assert updated.status == "resolved"
        assert updated.resolved_at is not None
        assert "False positive" in updated.resolution_notes

    def test_update_nonexistent_alert(self):
        """Test updating a non-existent alert."""
        manager = AlertManager()

        result = manager.update_alert_status("nonexistent-id", "resolved")

        assert result is None


class TestAlertManagerStatistics:
    """Tests for alert statistics."""

    def test_get_statistics_empty(self):
        """Test statistics when no alerts exist."""
        manager = AlertManager()
        stats = manager.get_alert_statistics()

        assert stats["total"] == 0
        assert stats["by_severity"] == {}
        assert stats["by_status"] == {}
        assert stats["open_critical"] == 0

    def test_get_statistics_with_alerts(self):
        """Test statistics calculation with alerts."""
        manager = AlertManager()

        # Create alerts with various severities and statuses
        alerts_data = [
            (AlertSeverity.LOW, "new"),
            (AlertSeverity.MEDIUM, "new"),
            (AlertSeverity.MEDIUM, "acknowledged"),
            (AlertSeverity.HIGH, "investigating"),
            (AlertSeverity.CRITICAL, "new"),
            (AlertSeverity.CRITICAL, "resolved"),
        ]

        for i, (severity, status) in enumerate(alerts_data):
            alert = Alert(
                id=f"alert-{i}",
                timestamp=datetime.now(),
                severity=severity,
                title=f"Alert {i}",
                description="Test",
                source="test",
                status=status
            )
            manager.alerts[alert.id] = alert

        stats = manager.get_alert_statistics()

        assert stats["total"] == 6
        assert stats["by_severity"]["low"] == 1
        assert stats["by_severity"]["medium"] == 2
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["critical"] == 2
        assert stats["by_status"]["new"] == 3
        assert stats["open_critical"] == 1  # Only 1 critical not resolved


class TestAlertCorrelation:
    """Tests for alert correlation."""

    def test_correlate_alerts_same_ip(self):
        """Test correlating alerts from the same IP."""
        manager = AlertManager()

        # Create first alert
        log1 = LogEntry(
            id="log-1",
            timestamp=datetime.now() - timedelta(minutes=5),
            level=LogLevel.WARNING,
            source=LogSource.AUTH,
            message="Failed login attempt",
            source_ip="192.168.1.100"
        )
        manager.process_logs([log1])

        # Create second alert from same IP
        log2 = LogEntry(
            id="log-2",
            timestamp=datetime.now(),
            level=LogLevel.WARNING,
            source=LogSource.AUTH,
            message="SQL injection attempt",
            source_ip="192.168.1.100"
        )
        manager.process_logs([log2])

        # Alerts should be correlated if within time window
        # The correlation happens internally in _correlate_alerts
        assert len(manager.alerts) >= 1

    def test_are_alerts_related_same_ip(self):
        """Test alert relation detection by IP."""
        manager = AlertManager()

        alert1 = Alert(
            id="alert-1",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Alert 1",
            description="Test",
            source="test",
            indicators={"source_ip": "192.168.1.100"}
        )

        alert2 = Alert(
            id="alert-2",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Alert 2",
            description="Test",
            source="test",
            indicators={"source_ip": "192.168.1.100"}
        )

        assert manager._are_alerts_related(alert1, alert2) is True

    def test_are_alerts_related_same_user(self):
        """Test alert relation detection by user."""
        manager = AlertManager()

        alert1 = Alert(
            id="alert-1",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Alert 1",
            description="Test",
            source="test",
            indicators={"user": "admin"}
        )

        alert2 = Alert(
            id="alert-2",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Alert 2",
            description="Test",
            source="test",
            indicators={"user": "admin"}
        )

        assert manager._are_alerts_related(alert1, alert2) is True

    def test_are_alerts_related_different_indicators(self):
        """Test that alerts with different indicators are not related."""
        manager = AlertManager()

        alert1 = Alert(
            id="alert-1",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Alert 1",
            description="Test",
            source="test",
            indicators={"source_ip": "192.168.1.100", "user": "admin"}
        )

        alert2 = Alert(
            id="alert-2",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Alert 2",
            description="Test",
            source="test",
            indicators={"source_ip": "192.168.1.200", "user": "guest"}
        )

        assert manager._are_alerts_related(alert1, alert2) is False
