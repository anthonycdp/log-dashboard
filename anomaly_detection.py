"""
Anomaly detection module for the Security Log Dashboard.
Implements statistical and pattern-based anomaly detection.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict, Counter
import statistics
import hashlib
import re
from models import LogEntry, AnomalyResult, LogLevel


class AnomalyDetector:
    """
    Detects anomalies in log patterns using various techniques:
    - Statistical analysis (z-score, percentiles)
    - Rate-based detection
    - Pattern analysis
    - Time-series analysis
    """

    def __init__(self):
        self.baseline_window = timedelta(hours=1)
        self.anomaly_threshold = 2.5  # Z-score threshold
        self.rate_threshold_multiplier = 3.0

        # Known malicious patterns
        self.suspicious_patterns = [
            (r'(?:failed|failure|invalid|denied).*login', 'failed_login_pattern'),
            (r'(?:error|exception).*database', 'database_error_pattern'),
            (r'(?:port scan|scan detected)', 'port_scan_pattern'),
            (r'(?:brute force|bruteforce)', 'brute_force_pattern'),
            (r'(?:injection|sql injection|xss)', 'injection_pattern'),
            (r'(?:unauthorized|forbidden)', 'unauthorized_access_pattern'),
            (r'(?:malware|virus|trojan)', 'malware_pattern'),
            (r'(?:DDoS|dos attack)', 'ddos_pattern'),
        ]

        # Known malicious IP ranges (example - in production use threat intel feeds)
        self.suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 4444, 6667, 31337]

        # Compile regex patterns
        self.compiled_patterns = [
            (re.compile(p, re.IGNORECASE), name)
            for p, name in self.suspicious_patterns
        ]

    def detect_anomalies(
        self,
        logs: List[LogEntry],
        baseline_logs: List[LogEntry] = None
    ) -> List[AnomalyResult]:
        """
        Main method to detect all types of anomalies in logs.
        """
        anomalies = []

        if not logs:
            return anomalies

        # Run various anomaly detection methods
        anomalies.extend(self._detect_rate_anomalies(logs, baseline_logs))
        anomalies.extend(self._detect_pattern_anomalies(logs))
        anomalies.extend(self._detect_ip_anomalies(logs, baseline_logs))
        anomalies.extend(self._detect_port_anomalies(logs))
        anomalies.extend(self._detect_time_anomalies(logs))
        anomalies.extend(self._detect_severity_anomalies(logs, baseline_logs))

        return anomalies

    def _detect_rate_anomalies(
        self,
        logs: List[LogEntry],
        baseline_logs: List[LogEntry] = None
    ) -> List[AnomalyResult]:
        """
        Detect unusual log rate patterns.
        """
        anomalies = []

        if not logs:
            return anomalies

        # Group logs by minute
        log_rates = self._group_logs_by_interval(logs, timedelta(minutes=1))

        if len(log_rates) < 5:
            return anomalies

        rates = list(log_rates.values())
        mean_rate = statistics.mean(rates)
        std_rate = statistics.stdev(rates) if len(rates) > 1 else 0

        if std_rate == 0:
            return anomalies

        for timestamp, count in log_rates.items():
            z_score = abs(count - mean_rate) / std_rate

            if z_score > self.anomaly_threshold:
                # Find logs in this time window
                window_logs = [
                    log for log in logs
                    if self._get_interval_key(log.timestamp, timedelta(minutes=1)) == timestamp
                ]

                if window_logs:
                    anomalies.append(AnomalyResult(
                        log_id=window_logs[0].id,
                        timestamp=timestamp,
                        anomaly_type="log_rate_spike",
                        score=min(z_score / 5.0, 1.0),
                        description=f"Unusual log rate detected: {count} logs/minute (baseline: {mean_rate:.1f})",
                        baseline_value=mean_rate,
                        observed_value=count,
                        details={
                            "z_score": z_score,
                            "window_logs": len(window_logs),
                            "sample_log_ids": [log.id for log in window_logs[:5]]
                        }
                    ))

        return anomalies

    def _detect_pattern_anomalies(self, logs: List[LogEntry]) -> List[AnomalyResult]:
        """
        Detect suspicious patterns in log messages.
        """
        anomalies = []

        for log in logs:
            for pattern, pattern_name in self.compiled_patterns:
                if pattern.search(log.message):
                    score = self._calculate_pattern_score(pattern_name, log)

                    anomalies.append(AnomalyResult(
                        log_id=log.id,
                        timestamp=log.timestamp,
                        anomaly_type=pattern_name,
                        score=score,
                        description=f"Suspicious pattern detected: {pattern_name}",
                        baseline_value=0,
                        observed_value=1,
                        details={
                            "matched_pattern": pattern_name,
                            "log_level": log.level.value,
                            "source": log.source.value,
                            "message_preview": log.message[:200]
                        }
                    ))

        return anomalies

    def _detect_ip_anomalies(
        self,
        logs: List[LogEntry],
        baseline_logs: List[LogEntry] = None
    ) -> List[AnomalyResult]:
        """
        Detect anomalies in IP address patterns.
        """
        anomalies = []

        # Count source IP occurrences
        ip_counter = Counter()
        ip_logs = defaultdict(list)

        for log in logs:
            if log.source_ip:
                ip_counter[log.source_ip] += 1
                ip_logs[log.source_ip].append(log)

        if not ip_counter:
            return anomalies

        # Calculate baseline
        baseline_ip_counter = Counter()
        if baseline_logs:
            for log in baseline_logs:
                if log.source_ip:
                    baseline_ip_counter[log.source_ip] += 1

        mean_count = statistics.mean(ip_counter.values()) if ip_counter else 0
        std_count = statistics.stdev(ip_counter.values()) if len(ip_counter) > 1 else 0

        for ip, count in ip_counter.most_common(50):
            # Check for rate anomaly
            if std_count > 0:
                z_score = abs(count - mean_count) / std_count

                if z_score > self.anomaly_threshold and count > 10:
                    log = ip_logs[ip][0]
                    anomalies.append(AnomalyResult(
                        log_id=log.id,
                        timestamp=log.timestamp,
                        anomaly_type="ip_rate_anomaly",
                        score=min(z_score / 5.0, 1.0),
                        description=f"Unusual activity from IP {ip}: {count} events",
                        baseline_value=mean_count,
                        observed_value=count,
                        details={
                            "ip_address": ip,
                            "event_count": count,
                            "z_score": z_score,
                            "log_ids": [l.id for l in ip_logs[ip][:10]]
                        }
                    ))

            # Check for new IP (not in baseline)
            if baseline_ip_counter and ip not in baseline_ip_counter and count > 5:
                log = ip_logs[ip][0]
                anomalies.append(AnomalyResult(
                    log_id=log.id,
                    timestamp=log.timestamp,
                    anomaly_type="new_ip_pattern",
                    score=0.6,
                    description=f"New IP detected with significant activity: {ip}",
                    baseline_value=0,
                    observed_value=count,
                    details={
                        "ip_address": ip,
                        "event_count": count,
                        "is_new": True
                    }
                ))

        return anomalies

    def _detect_port_anomalies(self, logs: List[LogEntry]) -> List[AnomalyResult]:
        """
        Detect suspicious port activity.
        """
        anomalies = []
        port_logs = defaultdict(list)

        for log in logs:
            if log.dest_port and log.dest_port in self.suspicious_ports:
                port_logs[log.dest_port].append(log)

        for port, port_log_list in port_logs.items():
            if len(port_log_list) >= 3:
                log = port_log_list[0]
                anomalies.append(AnomalyResult(
                    log_id=log.id,
                    timestamp=log.timestamp,
                    anomaly_type="suspicious_port_activity",
                    score=0.7,
                    description=f"Suspicious port activity detected on port {port}",
                    baseline_value=0,
                    observed_value=len(port_log_list),
                    details={
                        "port": port,
                        "event_count": len(port_log_list),
                        "source_ips": list(set(l.source_ip for l in port_log_list if l.source_ip))[:5]
                    }
                ))

        return anomalies

    def _detect_time_anomalies(self, logs: List[LogEntry]) -> List[AnomalyResult]:
        """
        Detect anomalies in timing patterns (e.g., activity during off-hours).
        """
        anomalies = []
        hour_activity = defaultdict(list)

        for log in logs:
            hour = log.timestamp.hour
            hour_activity[hour].append(log)

        # Define business hours (9 AM - 6 PM)
        business_hours = range(9, 18)

        for hour, hour_logs in hour_activity.items():
            if hour not in business_hours and len(hour_logs) > 50:
                # High activity during off-hours
                anomalies.append(AnomalyResult(
                    log_id=hour_logs[0].id,
                    timestamp=hour_logs[0].timestamp,
                    anomaly_type="off_hours_activity",
                    score=0.5,
                    description=f"High activity during off-hours ({hour}:00): {len(hour_logs)} events",
                    baseline_value=20,  # Expected baseline for off-hours
                    observed_value=len(hour_logs),
                    details={
                        "hour": hour,
                        "event_count": len(hour_logs),
                        "is_business_hours": False
                    }
                ))

        return anomalies

    def _detect_severity_anomalies(
        self,
        logs: List[LogEntry],
        baseline_logs: List[LogEntry] = None
    ) -> List[AnomalyResult]:
        """
        Detect unusual patterns in log severity levels.
        """
        anomalies = []

        # Count by severity
        severity_counts = Counter(log.level.value for log in logs)

        error_count = severity_counts.get(LogLevel.ERROR.value, 0)
        critical_count = severity_counts.get(LogLevel.CRITICAL.value, 0)
        total = len(logs)

        if total == 0:
            return anomalies

        error_rate = (error_count + critical_count) / total

        if error_rate > 0.1:  # More than 10% errors
            error_logs = [log for log in logs if log.level in [LogLevel.ERROR, LogLevel.CRITICAL]]

            if error_logs:
                anomalies.append(AnomalyResult(
                    log_id=error_logs[0].id,
                    timestamp=error_logs[0].timestamp,
                    anomaly_type="high_error_rate",
                    score=min(error_rate * 5, 1.0),
                    description=f"High error rate detected: {error_rate*100:.1f}%",
                    baseline_value=0.05,  # 5% baseline
                    observed_value=error_rate,
                    details={
                        "error_count": error_count,
                        "critical_count": critical_count,
                        "total_logs": total,
                        "error_rate": error_rate
                    }
                ))

        return anomalies

    def _group_logs_by_interval(
        self,
        logs: List[LogEntry],
        interval: timedelta
    ) -> Dict[datetime, int]:
        """Group logs by time interval."""
        groups = defaultdict(int)

        for log in logs:
            key = self._get_interval_key(log.timestamp, interval)
            groups[key] += 1

        return dict(groups)

    def _get_interval_key(self, timestamp: datetime, interval: timedelta) -> datetime:
        """Get interval key for a timestamp."""
        interval_seconds = int(interval.total_seconds())
        epoch = datetime(1970, 1, 1)
        seconds = (timestamp - epoch).total_seconds()
        interval_number = int(seconds // interval_seconds)
        return epoch + timedelta(seconds=interval_number * interval_seconds)

    def _calculate_pattern_score(self, pattern_name: str, log: LogEntry) -> float:
        """Calculate anomaly score based on pattern and log context."""
        base_scores = {
            'malware_pattern': 0.95,
            'injection_pattern': 0.9,
            'brute_force_pattern': 0.85,
            'ddos_pattern': 0.85,
            'port_scan_pattern': 0.8,
            'unauthorized_access_pattern': 0.75,
            'failed_login_pattern': 0.6,
            'database_error_pattern': 0.5,
        }

        score = base_scores.get(pattern_name, 0.5)

        # Increase score for critical/error logs
        if log.level == LogLevel.CRITICAL:
            score = min(score * 1.3, 1.0)
        elif log.level == LogLevel.ERROR:
            score = min(score * 1.2, 1.0)

        return score


class BaselineCalculator:
    """
    Calculates baseline statistics for anomaly detection.
    """

    def __init__(self):
        self.baseline_data = {}

    def calculate_baseline(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Calculate baseline statistics from historical logs."""
        if not logs:
            return {}

        # Time-based statistics
        log_rates = self._calculate_hourly_rates(logs)

        # IP statistics
        ip_stats = self._calculate_ip_stats(logs)

        # Severity distribution
        severity_dist = Counter(log.level.value for log in logs)

        # Source distribution
        source_dist = Counter(log.source.value for log in logs)

        return {
            "log_rate_mean": statistics.mean(log_rates) if log_rates else 0,
            "log_rate_std": statistics.stdev(log_rates) if len(log_rates) > 1 else 0,
            "top_ips": dict(ip_stats.most_common(100)),
            "severity_distribution": dict(severity_dist),
            "source_distribution": dict(source_dist),
            "total_logs": len(logs),
            "time_range": {
                "start": min(log.timestamp for log in logs).isoformat(),
                "end": max(log.timestamp for log in logs).isoformat()
            }
        }

    def _calculate_hourly_rates(self, logs: List[LogEntry]) -> List[float]:
        """Calculate hourly log rates."""
        hour_counts = defaultdict(int)

        for log in logs:
            hour_key = log.timestamp.replace(minute=0, second=0, microsecond=0)
            hour_counts[hour_key] += 1

        return list(hour_counts.values())

    def _calculate_ip_stats(self, logs: List[LogEntry]) -> Counter:
        """Calculate IP occurrence statistics."""
        ip_counter = Counter()

        for log in logs:
            if log.source_ip:
                ip_counter[log.source_ip] += 1

        return ip_counter
