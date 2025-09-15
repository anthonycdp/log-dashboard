"""
Alert management module for the Security Log Dashboard.
Handles alert generation, correlation, and lifecycle management.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict
import uuid
import re

from models import LogEntry, Alert, AlertSeverity, AnomalyResult, LogLevel


class AlertRule:
    """Base class for alert rules."""

    def __init__(
        self,
        name: str,
        severity: AlertSeverity,
        description: str,
        cooldown_minutes: int = 60
    ):
        self.name = name
        self.severity = severity
        self.description = description
        self.cooldown = timedelta(minutes=cooldown_minutes)
        self.last_triggered: Dict[str, datetime] = {}

    def should_trigger(self, key: str) -> bool:
        """Check if rule can trigger (respecting cooldown)."""
        if key not in self.last_triggered:
            return True
        return datetime.now() - self.last_triggered[key] > self.cooldown

    def mark_triggered(self, key: str):
        """Mark rule as triggered for a key."""
        self.last_triggered[key] = datetime.now()


class AlertManager:
    """
    Manages alert generation, correlation, and lifecycle.
    """

    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.alert_rules = self._initialize_rules()
        self.correlation_window = timedelta(minutes=30)

    def _initialize_rules(self) -> List[AlertRule]:
        """Initialize default alert rules."""
        return [
            AlertRule(
                name="multiple_failed_logins",
                severity=AlertSeverity.MEDIUM,
                description="Multiple failed login attempts detected",
                cooldown_minutes=30
            ),
            AlertRule(
                name="brute_force_detected",
                severity=AlertSeverity.HIGH,
                description="Brute force attack pattern detected",
                cooldown_minutes=15
            ),
            AlertRule(
                name="port_scan_detected",
                severity=AlertSeverity.MEDIUM,
                description="Port scanning activity detected",
                cooldown_minutes=60
            ),
            AlertRule(
                name="sql_injection_attempt",
                severity=AlertSeverity.HIGH,
                description="SQL injection attempt detected",
                cooldown_minutes=5
            ),
            AlertRule(
                name="unauthorized_access",
                severity=AlertSeverity.HIGH,
                description="Unauthorized access attempt",
                cooldown_minutes=5
            ),
            AlertRule(
                name="malware_signature",
                severity=AlertSeverity.CRITICAL,
                description="Malware signature detected",
                cooldown_minutes=0
            ),
            AlertRule(
                name="ddos_attack",
                severity=AlertSeverity.CRITICAL,
                description="DDoS attack detected",
                cooldown_minutes=10
            ),
            AlertRule(
                name="data_exfiltration",
                severity=AlertSeverity.CRITICAL,
                description="Potential data exfiltration detected",
                cooldown_minutes=5
            ),
            AlertRule(
                name="privilege_escalation",
                severity=AlertSeverity.HIGH,
                description="Privilege escalation attempt",
                cooldown_minutes=10
            ),
            AlertRule(
                name="anomalous_activity",
                severity=AlertSeverity.MEDIUM,
                description="Anomalous activity pattern detected",
                cooldown_minutes=30
            ),
        ]

    def process_logs(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Process logs and generate alerts based on rules.
        """
        new_alerts = []

        # Group logs by source IP for correlation
        logs_by_ip = defaultdict(list)
        for log in logs:
            if log.source_ip:
                logs_by_ip[log.source_ip].append(log)

        # Check each alert rule
        for log in logs:
            rule_alerts = self._check_rules(log, logs_by_ip)
            new_alerts.extend(rule_alerts)

        # Correlate with existing alerts
        self._correlate_alerts(new_alerts)

        # Store new alerts
        for alert in new_alerts:
            self.alerts[alert.id] = alert

        return new_alerts

    def process_anomalies(self, anomalies: List[AnomalyResult], logs: List[LogEntry]) -> List[Alert]:
        """
        Generate alerts from anomaly detection results.
        """
        new_alerts = []
        log_map = {log.id: log for log in logs}

        for anomaly in anomalies:
            # Only create alerts for high-confidence anomalies
            if anomaly.score >= 0.7:
                log = log_map.get(anomaly.log_id)

                if log:
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        timestamp=anomaly.timestamp,
                        severity=self._map_anomaly_to_severity(anomaly.score),
                        title=f"Anomaly Detected: {anomaly.anomaly_type}",
                        description=anomaly.description,
                        source="anomaly_detector",
                        related_logs=[anomaly.log_id],
                        status="new",
                        indicators={
                            "anomaly_type": anomaly.anomaly_type,
                            "score": anomaly.score,
                            "baseline": anomaly.baseline_value,
                            "observed": anomaly.observed_value,
                            "source_ip": log.source_ip,
                            "user": log.user
                        }
                    )
                    new_alerts.append(alert)

        for alert in new_alerts:
            self.alerts[alert.id] = alert

        return new_alerts

    def _check_rules(self, log: LogEntry, logs_by_ip: Dict[str, List[LogEntry]]) -> List[Alert]:
        """Check log against all alert rules."""
        alerts = []
        message_lower = log.message.lower()

        # Multiple failed logins rule
        if self._check_failed_logins_rule(log, logs_by_ip, message_lower):
            alerts.append(self._create_login_alert(log, logs_by_ip))

        # SQL injection rule
        if self._check_sql_injection_rule(log, message_lower):
            alerts.append(self._create_sql_injection_alert(log))

        # Port scan rule
        if self._check_port_scan_rule(log, logs_by_ip):
            alerts.append(self._create_port_scan_alert(log, logs_by_ip))

        # DDoS rule
        if self._check_ddos_rule(log, logs_by_ip):
            alerts.append(self._create_ddos_alert(log, logs_by_ip))

        # Malware signature rule
        if self._check_malware_rule(log, message_lower):
            alerts.append(self._create_malware_alert(log))

        # Unauthorized access rule
        if self._check_unauthorized_rule(log, message_lower):
            alerts.append(self._create_unauthorized_alert(log))

        return alerts

    def _check_failed_logins_rule(self, log: LogEntry, logs_by_ip: Dict[str, List[LogEntry]], message: str) -> bool:
        """Check for multiple failed login pattern."""
        patterns = ['failed', 'failure', 'invalid', 'denied']
        if not any(p in message for p in patterns):
            return False

        if not log.source_ip:
            return False

        rule = next((r for r in self.alert_rules if r.name == "multiple_failed_logins"), None)
        if not rule or not rule.should_trigger(log.source_ip):
            return False

        # Count failed logins from same IP
        ip_logs = logs_by_ip.get(log.source_ip, [])
        failed_count = sum(1 for l in ip_logs if any(p in l.message.lower() for p in patterns))

        return failed_count >= 5

    def _create_login_alert(self, log: LogEntry, logs_by_ip: Dict[str, List[LogEntry]]) -> Alert:
        """Create alert for failed login attempts."""
        rule = next(r for r in self.alert_rules if r.name == "multiple_failed_logins")
        rule.mark_triggered(log.source_ip)

        ip_logs = logs_by_ip.get(log.source_ip, [])
        related_ids = [l.id for l in ip_logs if 'failed' in l.message.lower() or 'failure' in l.message.lower()]

        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH if len(related_ids) >= 10 else AlertSeverity.MEDIUM,
            title="Multiple Failed Login Attempts",
            description=f"Detected {len(related_ids)} failed login attempts from {log.source_ip}",
            source="login_monitor",
            related_logs=related_ids[:20],
            status="new",
            indicators={
                "source_ip": log.source_ip,
                "attempt_count": len(related_ids),
                "target_users": list(set(l.user for l in ip_logs if l.user))[:5]
            }
        )

    def _check_sql_injection_rule(self, log: LogEntry, message: str) -> bool:
        """Check for SQL injection patterns."""
        sql_patterns = [
            r"(?:union\s+select|select\s+.*\s+from)",
            r"(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
            r"(?:;\s*drop\s+table|;\s*delete\s+from)",
            r"(?:'\s*or\s*'|\"\s*or\s*\")",
            r"(?:sql\s*injection|injection\s*attempt)",
        ]

        for pattern in sql_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return True
        return False

    def _create_sql_injection_alert(self, log: LogEntry) -> Alert:
        """Create alert for SQL injection attempt."""
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="SQL Injection Attempt Detected",
            description=f"Potential SQL injection attempt from {log.source_ip}",
            source="sql_injection_monitor",
            related_logs=[log.id],
            status="new",
            indicators={
                "source_ip": log.source_ip,
                "target_endpoint": log.metadata.get("endpoint"),
                "payload_sample": log.message[:200]
            }
        )

    def _check_port_scan_rule(self, log: LogEntry, logs_by_ip: Dict[str, List[LogEntry]]) -> bool:
        """Check for port scanning activity."""
        if not log.source_ip:
            return False

        ip_logs = logs_by_ip.get(log.source_ip, [])
        unique_ports = set(l.dest_port for l in ip_logs if l.dest_port)

        return len(unique_ports) >= 10

    def _create_port_scan_alert(self, log: LogEntry, logs_by_ip: Dict[str, List[LogEntry]]) -> Alert:
        """Create alert for port scanning."""
        ip_logs = logs_by_ip.get(log.source_ip, [])
        unique_ports = sorted(set(l.dest_port for l in ip_logs if l.dest_port))

        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=AlertSeverity.MEDIUM,
            title="Port Scanning Activity Detected",
            description=f"Port scanning detected from {log.source_ip}: {len(unique_ports)} ports scanned",
            source="port_scan_monitor",
            related_logs=[l.id for l in ip_logs[:20]],
            status="new",
            indicators={
                "source_ip": log.source_ip,
                "ports_scanned": unique_ports[:50],
                "scan_count": len(unique_ports)
            }
        )

    def _check_ddos_rule(self, log: LogEntry, logs_by_ip: Dict[str, List[LogEntry]]) -> bool:
        """Check for DDoS patterns."""
        # Check for high volume from multiple IPs
        if len(logs_by_ip) < 10:
            return False

        total_events = sum(len(ip_logs) for ip_logs in logs_by_ip.values())
        return total_events > 1000

    def _create_ddos_alert(self, log: LogEntry, logs_by_ip: Dict[str, List[LogEntry]]) -> Alert:
        """Create alert for DDoS attack."""
        total_events = sum(len(ip_logs) for ip_logs in logs_by_ip.values())
        top_ips = sorted(logs_by_ip.keys(), key=lambda x: len(logs_by_ip[x]), reverse=True)[:10]

        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=AlertSeverity.CRITICAL,
            title="Potential DDoS Attack Detected",
            description=f"High volume attack from {len(logs_by_ip)} IPs: {total_events} events",
            source="ddos_monitor",
            related_logs=[],
            status="new",
            indicators={
                "total_events": total_events,
                "unique_ips": len(logs_by_ip),
                "top_source_ips": top_ips,
                "attack_type": "volume_based"
            }
        )

    def _check_malware_rule(self, log: LogEntry, message: str) -> bool:
        """Check for malware signatures."""
        malware_indicators = [
            'malware', 'virus', 'trojan', 'ransomware',
            'backdoor', 'worm', 'exploit', 'payload',
            'c2', 'command and control', 'botnet'
        ]
        return any(indicator in message for indicator in malware_indicators)

    def _create_malware_alert(self, log: LogEntry) -> Alert:
        """Create alert for malware detection."""
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=AlertSeverity.CRITICAL,
            title="Malware Signature Detected",
            description=f"Malware signature detected on {log.hostname or log.source_ip}",
            source="malware_detector",
            related_logs=[log.id],
            status="new",
            indicators={
                "source_ip": log.source_ip,
                "hostname": log.hostname,
                "infected_file": log.metadata.get("file"),
                "signature": log.metadata.get("signature")
            }
        )

    def _check_unauthorized_rule(self, log: LogEntry, message: str) -> bool:
        """Check for unauthorized access."""
        patterns = ['unauthorized', 'forbidden', 'access denied', 'permission denied']
        return any(p in message for p in patterns)

    def _create_unauthorized_alert(self, log: LogEntry) -> Alert:
        """Create alert for unauthorized access."""
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Unauthorized Access Attempt",
            description=f"Unauthorized access attempt from {log.source_ip}",
            source="access_monitor",
            related_logs=[log.id],
            status="new",
            indicators={
                "source_ip": log.source_ip,
                "user": log.user,
                "resource": log.metadata.get("resource"),
                "action": log.metadata.get("action")
            }
        )

    def _map_anomaly_to_severity(self, score: float) -> AlertSeverity:
        """Map anomaly score to alert severity."""
        if score >= 0.9:
            return AlertSeverity.CRITICAL
        elif score >= 0.8:
            return AlertSeverity.HIGH
        elif score >= 0.7:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def _correlate_alerts(self, new_alerts: List[Alert]):
        """Correlate new alerts with existing ones."""
        for alert in new_alerts:
            # Find related alerts within correlation window
            related = [
                existing for existing in self.alerts.values()
                if abs((existing.timestamp - alert.timestamp).total_seconds()) < self.correlation_window.total_seconds()
                and existing.id != alert.id
                and self._are_alerts_related(existing, alert)
            ]

            if related:
                # Link related alert IDs
                alert.related_logs.extend(
                    log_id for a in related for log_id in a.related_logs
                    if log_id not in alert.related_logs
                )

    def _are_alerts_related(self, alert1: Alert, alert2: Alert) -> bool:
        """Check if two alerts are related."""
        # Check for same source IP
        ip1 = alert1.indicators.get("source_ip")
        ip2 = alert2.indicators.get("source_ip")
        if ip1 and ip2 and ip1 == ip2:
            return True

        # Check for same user
        user1 = alert1.indicators.get("user")
        user2 = alert2.indicators.get("user")
        if user1 and user2 and user1 == user2:
            return True

        # Check for similar alert type
        if alert1.title == alert2.title:
            return True

        return False

    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[AlertSeverity] = None,
        limit: int = 100
    ) -> List[Alert]:
        """Get alerts with optional filtering."""
        alerts = list(self.alerts.values())

        if status:
            alerts = [a for a in alerts if a.status == status]

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        # Sort by timestamp descending
        alerts.sort(key=lambda x: x.timestamp, reverse=True)

        return alerts[:limit]

    def update_alert_status(
        self,
        alert_id: str,
        status: str,
        assigned_to: Optional[str] = None,
        resolution_notes: Optional[str] = None
    ) -> Optional[Alert]:
        """Update alert status."""
        alert = self.alerts.get(alert_id)
        if not alert:
            return None

        alert.status = status

        if assigned_to:
            alert.assigned_to = assigned_to

        if status == "resolved":
            alert.resolved_at = datetime.now()
            alert.resolution_notes = resolution_notes

        return alert

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        alerts = list(self.alerts.values())

        if not alerts:
            return {
                "total": 0,
                "by_severity": {},
                "by_status": {},
                "open_critical": 0
            }

        by_severity = defaultdict(int)
        by_status = defaultdict(int)
        open_critical = 0

        for alert in alerts:
            by_severity[alert.severity.value] += 1
            by_status[alert.status] += 1

            if alert.severity == AlertSeverity.CRITICAL and alert.status != "resolved":
                open_critical += 1

        return {
            "total": len(alerts),
            "by_severity": dict(by_severity),
            "by_status": dict(by_status),
            "open_critical": open_critical
        }
