"""
Pytest configuration and shared fixtures for Security Log Dashboard tests.
"""

import pytest
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    LogEntry, Alert, AnomalyResult, LogLevel, LogSource, AlertSeverity,
    SearchQuery, SearchResponse, LogStatistics, DashboardMetrics, TimelineEvent
)


@pytest.fixture
def sample_log_entry():
    """Create a sample log entry for testing."""
    return LogEntry(
        id="log-001",
        timestamp=datetime.now(),
        level=LogLevel.INFO,
        source=LogSource.AUTH,
        message="User login successful",
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        source_port=54321,
        dest_port=443,
        protocol="HTTPS",
        user="admin",
        hostname="server01",
        process="sshd",
        tags=["authentication"],
        metadata={"session_id": "abc123"}
    )


@pytest.fixture
def sample_error_log():
    """Create a sample error log entry."""
    return LogEntry(
        id="log-002",
        timestamp=datetime.now(),
        level=LogLevel.ERROR,
        source=LogSource.DATABASE,
        message="Database connection failed",
        source_ip="192.168.1.101",
        user="db_user",
        tags=["database", "error"]
    )


@pytest.fixture
def sample_critical_log():
    """Create a sample critical log entry."""
    return LogEntry(
        id="log-003",
        timestamp=datetime.now(),
        level=LogLevel.CRITICAL,
        source=LogSource.IDS,
        message="Malware signature detected in network traffic",
        source_ip="10.0.0.50",
        dest_ip="192.168.1.200",
        dest_port=4444,
        tags=["malware", "critical"]
    )


@pytest.fixture
def sample_logs_list(sample_log_entry, sample_error_log, sample_critical_log):
    """Create a list of sample log entries."""
    return [sample_log_entry, sample_error_log, sample_critical_log]


@pytest.fixture
def sample_failed_login_logs():
    """Create multiple failed login log entries for testing brute force detection."""
    logs = []
    base_time = datetime.now() - timedelta(minutes=30)
    source_ip = "192.168.1.200"

    for i in range(10):
        logs.append(LogEntry(
            id=f"failed-login-{i}",
            timestamp=base_time + timedelta(seconds=i * 30),
            level=LogLevel.WARNING,
            source=LogSource.AUTH,
            message=f"Failed login attempt for user admin",
            source_ip=source_ip,
            user="admin",
            tags=["authentication", "failed"]
        ))

    return logs


@pytest.fixture
def sample_sql_injection_log():
    """Create a log entry with SQL injection pattern."""
    return LogEntry(
        id="sql-injection-001",
        timestamp=datetime.now(),
        level=LogLevel.ERROR,
        source=LogSource.WEB_SERVER,
        message="SQL injection attempt detected: ' OR 1=1 -- in query parameter",
        source_ip="10.0.0.100",
        user="anonymous",
        metadata={"endpoint": "/api/users", "parameter": "id"}
    )


@pytest.fixture
def sample_port_scan_logs():
    """Create logs simulating port scanning activity."""
    logs = []
    base_time = datetime.now() - timedelta(minutes=10)
    source_ip = "192.168.100.50"

    # Scan 15 different ports
    for i, port in enumerate([22, 23, 80, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 5672, 9092]):
        logs.append(LogEntry(
            id=f"port-scan-{i}",
            timestamp=base_time + timedelta(seconds=i * 5),
            level=LogLevel.WARNING,
            source=LogSource.FIREWALL,
            message=f"Connection attempt to closed port {port}",
            source_ip=source_ip,
            dest_ip="10.0.0.1",
            dest_port=port,
            tags=["firewall", "scan"]
        ))

    return logs


@pytest.fixture
def sample_alert():
    """Create a sample alert for testing."""
    return Alert(
        id="alert-001",
        timestamp=datetime.now(),
        severity=AlertSeverity.HIGH,
        title="Multiple Failed Login Attempts",
        description="Detected 10 failed login attempts from 192.168.1.200",
        source="login_monitor",
        related_logs=["log-001", "log-002"],
        status="new",
        indicators={"source_ip": "192.168.1.200", "attempt_count": 10}
    )


@pytest.fixture
def sample_anomaly_result():
    """Create a sample anomaly result for testing."""
    return AnomalyResult(
        log_id="log-001",
        timestamp=datetime.now(),
        anomaly_type="log_rate_spike",
        score=0.85,
        description="Unusual log rate detected: 500 logs/minute",
        baseline_value=100.0,
        observed_value=500.0,
        details={"z_score": 3.5}
    )


@pytest.fixture
def logs_with_rate_anomaly():
    """Create logs with a rate anomaly pattern."""
    logs = []
    base_time = datetime.now() - timedelta(hours=1)

    # Normal rate for first 30 minutes (10 logs per minute)
    for minute in range(30):
        for i in range(10):
            logs.append(LogEntry(
                id=f"normal-{minute}-{i}",
                timestamp=base_time + timedelta(minutes=minute, seconds=i * 6),
                level=LogLevel.INFO,
                source=LogSource.SYSTEM,
                message="Normal system log entry",
                source_ip="10.0.0.1",
                tags=["system"]
            ))

    # Spike in the last 30 minutes (100 logs per minute for 5 minutes)
    spike_time = base_time + timedelta(minutes=30)
    for minute in range(5):
        for i in range(100):
            logs.append(LogEntry(
                id=f"spike-{minute}-{i}",
                timestamp=spike_time + timedelta(minutes=minute, seconds=i * 0.6),
                level=LogLevel.WARNING,
                source=LogSource.SYSTEM,
                message="High activity log entry",
                source_ip="10.0.0.1",
                tags=["system", "high-activity"]
            ))

    return logs


@pytest.fixture
def ddos_attack_logs():
    """Create logs simulating a DDoS attack."""
    logs = []
    base_time = datetime.now() - timedelta(minutes=5)

    # Simulate traffic from 50 different IPs
    for ip_num in range(50):
        source_ip = f"10.100.{ip_num // 256}.{ip_num % 256}"
        for i in range(30):  # 30 events per IP
            logs.append(LogEntry(
                id=f"ddos-{ip_num}-{i}",
                timestamp=base_time + timedelta(seconds=i * 10),
                level=LogLevel.WARNING,
                source=LogSource.FIREWALL,
                message="High volume connection",
                source_ip=source_ip,
                dest_ip="10.0.0.1",
                dest_port=80,
                tags=["firewall", "ddos"]
            ))

    return logs
