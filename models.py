"""
Data models for the Security Log Dashboard.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class LogLevel(str, Enum):
    """Log severity levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogSource(str, Enum):
    """Log source types."""
    FIREWALL = "firewall"
    IDS = "ids"
    AUTH = "authentication"
    WEB_SERVER = "web_server"
    DATABASE = "database"
    SYSTEM = "system"
    APPLICATION = "application"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogEntry(BaseModel):
    """Individual log entry model."""
    id: str = Field(..., description="Unique log entry identifier")
    timestamp: datetime = Field(..., description="Log timestamp")
    level: LogLevel = Field(..., description="Log severity level")
    source: LogSource = Field(..., description="Log source")
    message: str = Field(..., description="Log message content")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    dest_ip: Optional[str] = Field(None, description="Destination IP address")
    source_port: Optional[int] = Field(None, description="Source port")
    dest_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[str] = Field(None, description="Network protocol")
    user: Optional[str] = Field(None, description="Associated user")
    hostname: Optional[str] = Field(None, description="Source hostname")
    process: Optional[str] = Field(None, description="Process name")
    raw_log: Optional[str] = Field(None, description="Original raw log")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class Alert(BaseModel):
    """Security alert model."""
    id: str = Field(..., description="Unique alert identifier")
    timestamp: datetime = Field(..., description="Alert timestamp")
    severity: AlertSeverity = Field(..., description="Alert severity")
    title: str = Field(..., description="Alert title")
    description: str = Field(..., description="Alert description")
    source: str = Field(..., description="Alert source/rule")
    related_logs: List[str] = Field(default_factory=list, description="Related log IDs")
    status: str = Field(default="new", description="Alert status")
    assigned_to: Optional[str] = Field(None, description="Assigned analyst")
    resolved_at: Optional[datetime] = Field(None, description="Resolution timestamp")
    resolution_notes: Optional[str] = Field(None, description="Resolution notes")
    indicators: Dict[str, Any] = Field(default_factory=dict, description="Threat indicators")


class AnomalyResult(BaseModel):
    """Anomaly detection result model."""
    log_id: str = Field(..., description="Related log entry ID")
    timestamp: datetime = Field(..., description="Detection timestamp")
    anomaly_type: str = Field(..., description="Type of anomaly detected")
    score: float = Field(..., ge=0.0, le=1.0, description="Anomaly confidence score")
    description: str = Field(..., description="Anomaly description")
    baseline_value: float = Field(..., description="Expected baseline value")
    observed_value: float = Field(..., description="Observed value")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")


class TimelineEvent(BaseModel):
    """Timeline event for incident investigation."""
    timestamp: datetime = Field(..., description="Event timestamp")
    event_type: str = Field(..., description="Type of event")
    description: str = Field(..., description="Event description")
    source: str = Field(..., description="Event source")
    related_ips: List[str] = Field(default_factory=list, description="Related IP addresses")
    related_users: List[str] = Field(default_factory=list, description="Related users")
    severity: str = Field(default="info", description="Event severity")
    log_ids: List[str] = Field(default_factory=list, description="Related log IDs")


class SearchQuery(BaseModel):
    """Search query model for log filtering."""
    query: Optional[str] = Field(None, description="Full-text search query")
    start_time: Optional[datetime] = Field(None, description="Start time filter")
    end_time: Optional[datetime] = Field(None, description="End time filter")
    levels: Optional[List[LogLevel]] = Field(None, description="Filter by log levels")
    sources: Optional[List[LogSource]] = Field(None, description="Filter by sources")
    source_ips: Optional[List[str]] = Field(None, description="Filter by source IPs")
    dest_ips: Optional[List[str]] = Field(None, description="Filter by destination IPs")
    users: Optional[List[str]] = Field(None, description="Filter by users")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    limit: int = Field(default=100, ge=1, le=10000, description="Result limit")
    offset: int = Field(default=0, ge=0, description="Result offset")


class SearchResponse(BaseModel):
    """Search response with pagination."""
    results: List[LogEntry] = Field(..., description="Search results")
    total: int = Field(..., description="Total matching records")
    limit: int = Field(..., description="Applied limit")
    offset: int = Field(..., description="Applied offset")
    query_time_ms: float = Field(..., description="Query execution time in ms")


class LogStatistics(BaseModel):
    """Log statistics model."""
    total_logs: int = Field(..., description="Total log count")
    logs_by_level: Dict[str, int] = Field(..., description="Count by log level")
    logs_by_source: Dict[str, int] = Field(..., description="Count by source")
    top_source_ips: List[Dict[str, Any]] = Field(..., description="Top source IPs")
    top_dest_ips: List[Dict[str, Any]] = Field(..., description="Top destination IPs")
    error_rate: float = Field(..., description="Error rate percentage")
    time_range: Dict[str, str] = Field(..., description="Time range of logs")


class DashboardMetrics(BaseModel):
    """Dashboard metrics for overview."""
    total_logs_24h: int = Field(..., description="Logs in last 24 hours")
    alerts_24h: int = Field(..., description="Alerts in last 24 hours")
    anomalies_24h: int = Field(..., description="Anomalies in last 24 hours")
    critical_alerts: int = Field(..., description="Open critical alerts")
    top_threat_sources: List[Dict[str, Any]] = Field(..., description="Top threat sources")
    log_trend: List[Dict[str, Any]] = Field(..., description="Log count trend")
    alert_trend: List[Dict[str, Any]] = Field(..., description="Alert count trend")
