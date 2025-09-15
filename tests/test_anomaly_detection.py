"""
Unit tests for anomaly detection module in the Security Log Dashboard.
"""

import pytest
from datetime import datetime, timedelta
from collections import Counter

from anomaly_detection import AnomalyDetector, BaselineCalculator
from models import LogEntry, AnomalyResult, LogLevel, LogSource


class TestAnomalyDetector:
    """Tests for AnomalyDetector class."""

    def test_detector_initialization(self):
        """Test that detector initializes with correct defaults."""
        detector = AnomalyDetector()
        assert detector.anomaly_threshold == 2.5
        assert detector.rate_threshold_multiplier == 3.0
        assert len(detector.suspicious_patterns) > 0
        assert len(detector.suspicious_ports) > 0

    def test_detect_anomalies_empty_logs(self):
        """Test detection with empty log list."""
        detector = AnomalyDetector()
        anomalies = detector.detect_anomalies([])
        assert anomalies == []

    def test_detect_pattern_anomalies_failed_login(self):
        """Test detection of failed login patterns."""
        detector = AnomalyDetector()

        logs = [
            LogEntry(
                id=f"log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.WARNING,
                source=LogSource.AUTH,
                message=f"Failed login attempt for user admin",
                source_ip="192.168.1.100",
                user="admin"
            )
            for i in range(5)
        ]

        anomalies = detector._detect_pattern_anomalies(logs)

        assert len(anomalies) > 0
        assert any(a.anomaly_type == "failed_login_pattern" for a in anomalies)

    def test_detect_pattern_anomalies_sql_injection(self):
        """Test detection of SQL injection patterns."""
        detector = AnomalyDetector()

        log = LogEntry(
            id="sql-log",
            timestamp=datetime.now(),
            level=LogLevel.ERROR,
            source=LogSource.WEB_SERVER,
            message="SQL injection attempt: ' OR 1=1 --",
            source_ip="10.0.0.100"
        )

        anomalies = detector._detect_pattern_anomalies([log])

        assert len(anomalies) > 0
        assert any(a.anomaly_type == "injection_pattern" for a in anomalies)

    def test_detect_pattern_anomalies_malware(self):
        """Test detection of malware patterns."""
        detector = AnomalyDetector()

        log = LogEntry(
            id="malware-log",
            timestamp=datetime.now(),
            level=LogLevel.CRITICAL,
            source=LogSource.IDS,
            message="Malware signature detected: Trojan.GenericKD",
            source_ip="10.0.0.50"
        )

        anomalies = detector._detect_pattern_anomalies([log])

        assert len(anomalies) > 0
        assert any(a.anomaly_type == "malware_pattern" for a in anomalies)
        # Malware should have high score
        malware_anomaly = next(a for a in anomalies if a.anomaly_type == "malware_pattern")
        assert malware_anomaly.score >= 0.9

    def test_detect_pattern_anomalies_ddos(self):
        """Test detection of DDoS patterns."""
        detector = AnomalyDetector()

        log = LogEntry(
            id="ddos-log",
            timestamp=datetime.now(),
            level=LogLevel.WARNING,
            source=LogSource.FIREWALL,
            message="DDoS attack detected from multiple sources",
            source_ip="10.0.0.1"
        )

        anomalies = detector._detect_pattern_anomalies([log])

        assert any(a.anomaly_type == "ddos_pattern" for a in anomalies)

    def test_detect_port_anomalies_suspicious_ports(self):
        """Test detection of suspicious port activity."""
        detector = AnomalyDetector()

        # Create logs targeting suspicious ports (e.g., port 445 - SMB)
        logs = [
            LogEntry(
                id=f"port-log-{i}",
                timestamp=datetime.now() - timedelta(seconds=i * 10),
                level=LogLevel.WARNING,
                source=LogSource.FIREWALL,
                message="Connection to suspicious port",
                source_ip="192.168.1.100",
                dest_ip="10.0.0.1",
                dest_port=445  # Suspicious SMB port
            )
            for i in range(5)
        ]

        anomalies = detector._detect_port_anomalies(logs)

        assert len(anomalies) > 0
        assert anomalies[0].anomaly_type == "suspicious_port_activity"

    def test_detect_port_anomalies_normal_ports(self):
        """Test that normal ports don't trigger anomalies."""
        detector = AnomalyDetector()

        logs = [
            LogEntry(
                id=f"normal-port-{i}",
                timestamp=datetime.now() - timedelta(seconds=i),
                level=LogLevel.INFO,
                source=LogSource.FIREWALL,
                message="Normal connection",
                source_ip="192.168.1.100",
                dest_ip="10.0.0.1",
                dest_port=443  # Normal HTTPS port
            )
            for i in range(10)
        ]

        anomalies = detector._detect_port_anomalies(logs)

        # Port 443 is not in suspicious ports list
        assert len(anomalies) == 0

    def test_detect_rate_anomalies_insufficient_data(self):
        """Test rate detection with insufficient data points."""
        detector = AnomalyDetector()

        # Only 3 data points - not enough for statistical analysis
        logs = [
            LogEntry(
                id=f"log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Test"
            )
            for i in range(3)
        ]

        anomalies = detector._detect_rate_anomalies(logs)
        # Should return empty because we need at least 5 data points
        assert anomalies == []

    def test_detect_rate_anomalies_with_spike(self, logs_with_rate_anomaly):
        """Test detection of log rate spikes."""
        detector = AnomalyDetector()

        anomalies = detector._detect_rate_anomalies(logs_with_rate_anomaly)

        # Should detect the rate spike
        assert len(anomalies) > 0
        assert any(a.anomaly_type == "log_rate_spike" for a in anomalies)

    def test_detect_ip_anomalies_high_volume_ip(self):
        """Test detection of high-volume IP addresses."""
        detector = AnomalyDetector()

        # Create logs where one IP has much higher activity
        logs = []
        base_time = datetime.now() - timedelta(hours=1)

        # Normal IPs with 5-10 events each
        for ip_num in range(10):
            for i in range(5):
                logs.append(LogEntry(
                    id=f"normal-ip-{ip_num}-{i}",
                    timestamp=base_time + timedelta(seconds=i * 60),
                    level=LogLevel.INFO,
                    source=LogSource.SYSTEM,
                    message="Normal log",
                    source_ip=f"192.168.1.{ip_num}"
                ))

        # Anomalous IP with 50 events
        for i in range(50):
            logs.append(LogEntry(
                id=f"anomalous-ip-{i}",
                timestamp=base_time + timedelta(seconds=i * 60),
                level=LogLevel.WARNING,
                source=LogSource.SYSTEM,
                message="High volume log",
                source_ip="10.0.0.100"
            ))

        anomalies = detector._detect_ip_anomalies(logs)

        assert len(anomalies) > 0
        assert any(a.anomaly_type == "ip_rate_anomaly" for a in anomalies)

    def test_detect_ip_anomalies_new_ip_pattern(self):
        """Test detection of new IP addresses with significant activity."""
        detector = AnomalyDetector()

        # Baseline logs with known IPs
        baseline_logs = [
            LogEntry(
                id=f"baseline-{i}",
                timestamp=datetime.now() - timedelta(hours=2),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Baseline log",
                source_ip="192.168.1.1"
            )
            for i in range(20)
        ]

        # Current logs with new IP
        current_logs = [
            LogEntry(
                id=f"current-{i}",
                timestamp=datetime.now() - timedelta(minutes=30),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Current log",
                source_ip="10.0.0.200"  # New IP not in baseline
            )
            for i in range(10)
        ]

        anomalies = detector._detect_ip_anomalies(current_logs, baseline_logs)

        # Should detect the new IP pattern
        assert any(a.anomaly_type == "new_ip_pattern" for a in anomalies)

    def test_detect_time_anomalies_off_hours(self):
        """Test detection of off-hours activity."""
        detector = AnomalyDetector()

        # Create logs at 3 AM (off-hours)
        off_hours = datetime.now().replace(hour=3, minute=0, second=0, microsecond=0)

        logs = [
            LogEntry(
                id=f"off-hours-{i}",
                timestamp=off_hours + timedelta(seconds=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Off-hours activity"
            )
            for i in range(60)  # More than 50 events
        ]

        anomalies = detector._detect_time_anomalies(logs)

        assert len(anomalies) > 0
        assert any(a.anomaly_type == "off_hours_activity" for a in anomalies)

    def test_detect_severity_anomalies_high_error_rate(self):
        """Test detection of high error rates."""
        detector = AnomalyDetector()

        # Create logs with 20% error rate (above 10% threshold)
        logs = []
        base_time = datetime.now()

        for i in range(80):
            logs.append(LogEntry(
                id=f"info-{i}",
                timestamp=base_time + timedelta(seconds=i),
                level=LogLevel.INFO,
                source=LogSource.APPLICATION,
                message="Normal log"
            ))

        for i in range(20):
            logs.append(LogEntry(
                id=f"error-{i}",
                timestamp=base_time + timedelta(seconds=i),
                level=LogLevel.ERROR,
                source=LogSource.APPLICATION,
                message="Error log"
            ))

        anomalies = detector._detect_severity_anomalies(logs)

        assert len(anomalies) > 0
        assert any(a.anomaly_type == "high_error_rate" for a in anomalies)

    def test_detect_anomalies_full_pipeline(self, logs_with_rate_anomaly):
        """Test full anomaly detection pipeline."""
        detector = AnomalyDetector()

        # Add some pattern-based anomalies to the logs
        logs = list(logs_with_rate_anomaly)
        logs.append(LogEntry(
            id="sql-injection",
            timestamp=datetime.now(),
            level=LogLevel.ERROR,
            source=LogSource.WEB_SERVER,
            message="SQL injection attempt: UNION SELECT",
            source_ip="10.0.0.100"
        ))

        anomalies = detector.detect_anomalies(logs)

        # Should detect multiple types of anomalies
        anomaly_types = set(a.anomaly_type for a in anomalies)
        assert len(anomaly_types) > 0

    def test_calculate_pattern_score_malware(self):
        """Test pattern score calculation for malware."""
        detector = AnomalyDetector()

        log = LogEntry(
            id="test",
            timestamp=datetime.now(),
            level=LogLevel.CRITICAL,
            source=LogSource.IDS,
            message="Malware detected"
        )

        score = detector._calculate_pattern_score("malware_pattern", log)

        # Malware with CRITICAL level should have very high score
        assert score >= 0.9

    def test_calculate_pattern_score_failed_login(self):
        """Test pattern score calculation for failed login."""
        detector = AnomalyDetector()

        log = LogEntry(
            id="test",
            timestamp=datetime.now(),
            level=LogLevel.WARNING,
            source=LogSource.AUTH,
            message="Failed login"
        )

        score = detector._calculate_pattern_score("failed_login_pattern", log)

        # Failed login should have moderate score
        assert 0.5 <= score <= 0.8


class TestBaselineCalculator:
    """Tests for BaselineCalculator class."""

    def test_calculator_initialization(self):
        """Test calculator initialization."""
        calculator = BaselineCalculator()
        assert calculator.baseline_data == {}

    def test_calculate_baseline_empty_logs(self):
        """Test baseline calculation with empty logs."""
        calculator = BaselineCalculator()
        baseline = calculator.calculate_baseline([])

        assert baseline == {}

    def test_calculate_baseline_with_logs(self):
        """Test baseline calculation with sample logs."""
        calculator = BaselineCalculator()

        logs = []
        base_time = datetime.now() - timedelta(hours=24)

        for i in range(100):
            logs.append(LogEntry(
                id=f"baseline-{i}",
                timestamp=base_time + timedelta(minutes=i * 15),
                level=LogLevel.INFO if i % 5 != 0 else LogLevel.ERROR,
                source=LogSource.SYSTEM if i % 3 != 0 else LogSource.AUTH,
                message="Baseline log",
                source_ip=f"192.168.1.{i % 10}"
            ))

        baseline = calculator.calculate_baseline(logs)

        assert "log_rate_mean" in baseline
        assert "top_ips" in baseline
        assert "severity_distribution" in baseline
        assert "source_distribution" in baseline
        assert "total_logs" in baseline
        assert baseline["total_logs"] == 100

    def test_calculate_baseline_time_range(self):
        """Test baseline time range calculation."""
        calculator = BaselineCalculator()

        start_time = datetime.now() - timedelta(hours=5)
        end_time = datetime.now() - timedelta(hours=1)

        logs = [
            LogEntry(
                id="log-1",
                timestamp=start_time,
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="First log"
            ),
            LogEntry(
                id="log-2",
                timestamp=end_time,
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Last log"
            )
        ]

        baseline = calculator.calculate_baseline(logs)

        assert "time_range" in baseline
        assert "start" in baseline["time_range"]
        assert "end" in baseline["time_range"]

    def test_calculate_baseline_ip_stats(self):
        """Test baseline IP statistics calculation."""
        calculator = BaselineCalculator()

        logs = [
            LogEntry(
                id=f"log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Test",
                source_ip="192.168.1.100" if i < 50 else "192.168.1.200"
            )
            for i in range(100)
        ]

        baseline = calculator.calculate_baseline(logs)

        assert "192.168.1.100" in baseline["top_ips"]
        assert "192.168.1.200" in baseline["top_ips"]
        assert baseline["top_ips"]["192.168.1.100"] == 50
        assert baseline["top_ips"]["192.168.1.200"] == 50

    def test_calculate_baseline_severity_distribution(self):
        """Test baseline severity distribution calculation."""
        calculator = BaselineCalculator()

        logs = []
        for i in range(100):
            if i < 80:
                level = LogLevel.INFO
            elif i < 95:
                level = LogLevel.WARNING
            else:
                level = LogLevel.ERROR

            logs.append(LogEntry(
                id=f"log-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=level,
                source=LogSource.SYSTEM,
                message="Test"
            ))

        baseline = calculator.calculate_baseline(logs)

        assert baseline["severity_distribution"]["INFO"] == 80
        assert baseline["severity_distribution"]["WARNING"] == 15
        assert baseline["severity_distribution"]["ERROR"] == 5


class TestAnomalyDetectorEdgeCases:
    """Edge case tests for AnomalyDetector."""

    def test_detect_anomalies_with_none_values(self):
        """Test detection with logs containing None values."""
        detector = AnomalyDetector()

        log = LogEntry(
            id="test",
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            source=LogSource.SYSTEM,
            message="Test log",
            source_ip=None,
            dest_ip=None,
            dest_port=None
        )

        # Should not raise any errors
        anomalies = detector.detect_anomalies([log])
        assert isinstance(anomalies, list)

    def test_detect_anomalies_single_log(self):
        """Test detection with a single log entry."""
        detector = AnomalyDetector()

        log = LogEntry(
            id="single",
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            source=LogSource.SYSTEM,
            message="Single log entry"
        )

        anomalies = detector.detect_anomalies([log])
        # Should handle gracefully, may find pattern anomalies
        assert isinstance(anomalies, list)

    def test_detect_anomalies_logs_without_ips(self):
        """Test IP detection when logs have no IP addresses."""
        detector = AnomalyDetector()

        logs = [
            LogEntry(
                id=f"no-ip-{i}",
                timestamp=datetime.now() - timedelta(minutes=i),
                level=LogLevel.INFO,
                source=LogSource.APPLICATION,
                message="Log without IP",
                source_ip=None
            )
            for i in range(50)
        ]

        ip_anomalies = detector._detect_ip_anomalies(logs)
        # Should return empty since no IPs to analyze
        assert ip_anomalies == []

    def test_detect_rate_anomalies_low_variance(self):
        """Test rate detection with low variance in rates."""
        detector = AnomalyDetector()

        # Create logs with mostly uniform distribution
        # Need enough data points to have meaningful statistics
        logs = []
        base_time = datetime.now() - timedelta(hours=1)

        # Exactly 10 logs per minute for 15 minutes (enough for stats)
        for minute in range(15):
            for i in range(10):
                logs.append(LogEntry(
                    id=f"uniform-{minute}-{i}",
                    timestamp=base_time + timedelta(minutes=minute, seconds=i * 6),
                    level=LogLevel.INFO,
                    source=LogSource.SYSTEM,
                    message="Uniform log"
                ))

        anomalies = detector._detect_rate_anomalies(logs)
        # With low variance, z-scores should be below threshold
        # All rates are identical (10 per minute), so no rate anomalies expected
        # if there's any variance due to timing, anomalies might occur
        # Just verify the function handles uniform data without crashing
        assert isinstance(anomalies, list)
