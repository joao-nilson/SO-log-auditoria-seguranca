"""
Alert generation and management system for security events.
Processes alerts from Zeek SQLite database.
"""

import sqlite3
import logging
import yaml
import json
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Union, Any
import pandas as pd
from utils.time_utils import zeek_to_datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecurityAlert:
    """
    Data class representing a security alert.
    """
    alert_id: str
    timestamp: datetime
    severity: str  # 'low', 'medium', 'high', 'critical'
    category: str
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    evidence: Optional[Dict] = None
    status: str = 'open'  # 'open', 'investigating', 'resolved', 'false_positive'

class BatchAlertManager:
    def __init__(self, db_path: str, config_path: str = 'config/alert_rules.yml'):
        """
        Initialize the Batch Alert Manager with database and configuration.
        
        Args:
            db_path: Path to Zeek SQLite database
            config_path: Path to alert rules configuration file
        """
        self.db_path = db_path
        self.db_conn = sqlite3.connect(db_path)
        self.alerts: List[SecurityAlert] = []
        self.load_rules(config_path)
        self._setup_notification_channels()
        self.last_run_time = datetime.now() - timedelta(minutes=5)

    def load_rules(self, config_path: str) -> None:
        """
        Load alert rules from YAML configuration file.
        
        Args:
            config_path: Path to YAML config file
        """
        try:
            with open(config_path, 'r') as f:
                self.rules = yaml.safe_load(f) or {}
            logger.info(f"Loaded {len(self.rules)} alert rules from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load alert rules: {e}")
            self.rules = {}

    def _setup_notification_channels(self) -> None:
        """Initialize notification channels (email, Slack, etc.)"""
        # Placeholder - implement actual notification setup
        self.notification_channels = ['log']  # Default to just logging

    def run_detections(self) -> None:
        """
        Run all detection rules against the SQLite database.
        Only processes new data since the last run.
        """
        current_time = datetime.now()
        start_time = self.last_run_time
        end_time = current_time
        
        logger.info(f"Running detections from {start_time} to {end_time}")
        
        # Convert to Zeek timestamps
        start_ts = start_time.timestamp()
        end_ts = end_time.timestamp()
        
        # Run each detection rule
        for rule_name in self.rules:
            self._run_rule(rule_name, start_ts, end_ts)
        
        self.last_run_time = current_time
        logger.info(f"Detection completed. Found {len(self.alerts)} new alerts.")

    def _run_rule(self, rule_name: str, start_ts: float, end_ts: float) -> None:
        """
        Execute a specific detection rule against the database.
        
        Args:
            rule_name: Name of the rule to execute
            start_ts: Start timestamp (Zeek format)
            end_ts: End timestamp (Zeek format)
        """
        rule = self.rules.get(rule_name)
        if not rule:
            logger.warning(f"Rule {rule_name} not found in configuration")
            return
        
        # Determine which table to query
        log_type = rule.get('log_type', 'conn')
        
        try:
            # Build the SQL query based on rule type
            if rule_name == 'port_scan':
                self._detect_port_scans(rule, log_type, start_ts, end_ts)
            elif rule_name == 'long_connection':
                self._detect_long_connections(rule, log_type, start_ts, end_ts)
            elif rule_name == 'unusual_port':
                self._detect_unusual_ports(rule, log_type, start_ts, end_ts)
            elif rule_name == 'dns_tunneling':
                self._detect_dns_tunneling(rule, 'dns', start_ts, end_ts)
            elif rule_name == 'http_anomaly':
                self._detect_http_anomalies(rule, 'http', start_ts, end_ts)
            else:
                logger.warning(f"No detection method for rule: {rule_name}")
        except Exception as e:
            logger.error(f"Error executing rule {rule_name}: {e}")

    def _detect_port_scans(self, rule: Dict, log_type: str, start_ts: float, end_ts: float) -> None:
        """
        Detect port scans from connection logs.
        
        Args:
            rule: Port scan detection rules
            log_type: Log type to query ('conn')
            start_ts: Start timestamp
            end_ts: End timestamp
        """
        threshold = rule.get('threshold', 10)
        time_window = rule.get('time_window', 60)
        
        # Calculate time buckets
        bucket_size = time_window
        
        # Query to find source IPs scanning multiple ports in a time window
        query = f"""
        SELECT 
            `id.orig_h` AS source_ip,
            COUNT(DISTINCT `id.resp_p`) AS port_count,
            MIN(ts) AS first_scan,
            MAX(ts) AS last_scan
        FROM {log_type}
        WHERE 
            ts BETWEEN ? AND ?
            AND `id.resp_p` IS NOT NULL
            AND `id.orig_h` NOT IN ({self._format_exclusions(rule.get('exclude_ips', []))})
        GROUP BY `id.orig_h`, CAST(ts / {bucket_size} AS INTEGER)
        HAVING port_count > ?
        """
        
        params = [start_ts, end_ts, threshold]
        
        # Execute query and process results
        cursor = self.db_conn.cursor()
        cursor.execute(query, params)
        
        for row in cursor.fetchall():
            source_ip, port_count, first_scan, last_scan = row
            event_data = {
                'source_ip': source_ip,
                'port_count': port_count,
                'first_scan': first_scan,
                'last_scan': last_scan,
                'ts': last_scan  # Use last scan time as event timestamp
            }
            
            # Generate alert
            self._create_and_trigger_alert('port_scan', rule, event_data)

    def _detect_long_connections(self, rule: Dict, log_type: str, start_ts: float, end_ts: float) -> None:
        """
        Detect unusually long connections.
        
        Args:
            rule: Long connection detection rules
            log_type: Log type to query ('conn')
            start_ts: Start timestamp
            end_ts: End timestamp
        """
        duration_threshold = rule.get('threshold', 3600)  # 1 hour by default
        
        query = f"""
        SELECT *
        FROM {log_type}
        WHERE 
            duration > ?
            AND ts BETWEEN ? AND ?
            AND `id.orig_h` NOT IN ({self._format_exclusions(rule.get('exclude_ips', []))})
        """
        
        params = [duration_threshold, start_ts, end_ts]
        
        # Execute query and process results
        cursor = self.db_conn.cursor()
        cursor.execute(query, params)
        
        # Get column names
        columns = [d[0] for d in cursor.description]
        
        for row in cursor.fetchall():
            event_data = dict(zip(columns, row))
            self._create_and_trigger_alert('long_connection', rule, event_data)

    def _detect_unusual_ports(self, rule: Dict, log_type: str, start_ts: float, end_ts: float) -> None:
        """
        Detect connections to unusual ports.
        
        Args:
            rule: Unusual port detection rules
            log_type: Log type to query ('conn')
            start_ts: Start timestamp
            end_ts: End timestamp
        """
        common_ports = rule.get('common_ports', [80, 443, 22, 53])
        exclude_ips = rule.get('exclude_ips', [])
        
        query = f"""
        SELECT *
        FROM {log_type}
        WHERE 
            `id.resp_p` NOT IN ({','.join(['?']*len(common_ports))})
            AND ts BETWEEN ? AND ?
            AND `id.orig_h` NOT IN ({self._format_exclusions(exclude_ips)})
        """
        
        params = [*common_ports, start_ts, end_ts]
        
        # Execute query and process results
        cursor = self.db_conn.cursor()
        cursor.execute(query, params)
        
        # Get column names
        columns = [d[0] for d in cursor.description]
        
        for row in cursor.fetchall():
            event_data = dict(zip(columns, row))
            self._create_and_trigger_alert('unusual_port', rule, event_data)

    def _detect_dns_tunneling(self, rule: Dict, log_type: str, start_ts: float, end_ts: float) -> None:
        """
        Detect potential DNS tunneling activity.
        
        Args:
            rule: DNS tunneling detection rules
            log_type: Log type to query ('dns')
            start_ts: Start timestamp
            end_ts: End timestamp
        """
        query_length = rule.get('query_length', 50)
        subdomain_threshold = rule.get('subdomain_threshold', 5)
        
        query = f"""
        SELECT 
            `id.orig_h` AS source_ip,
            query,
            LENGTH(query) AS query_length,
            COUNT(*) AS request_count
        FROM {log_type}
        WHERE 
            ts BETWEEN ? AND ?
            AND LENGTH(query) > ?
        GROUP BY `id.orig_h`, query
        HAVING request_count > 1 OR (LENGTH(query) - LENGTH(REPLACE(query, '.', ''))) > ?
        """
        
        params = [start_ts, end_ts, query_length, subdomain_threshold]
        
        # Execute query and process results
        cursor = self.db_conn.cursor()
        cursor.execute(query, params)
        
        for row in cursor.fetchall():
            source_ip, query, query_length, request_count = row
            event_data = {
                'source_ip': source_ip,
                'query': query,
                'query_length': query_length,
                'request_count': request_count,
                'ts': end_ts  # Use end time as event timestamp
            }
            self._create_and_trigger_alert('dns_tunneling', rule, event_data)

    def _format_exclusions(self, exclude_list: list) -> str:
        """Format IP exclusions for SQL queries"""
        if not exclude_list:
            return "''"
        return ','.join([f"'{ip}'" for ip in exclude_list])

    def _create_and_trigger_alert(self, alert_type: str, rule: Dict, event_data: Dict) -> SecurityAlert:
        """
        Create and trigger an alert from database event data.
        
        Args:
            alert_type: Type of alert
            rule: Alert rule configuration
            event_data: Event data from database
            
        Returns:
            Created SecurityAlert object
        """
        alert = self._create_alert(alert_type, rule, event_data)
        
        if alert:
            self.alerts.append(alert)
            self._notify(alert)
            self._log_alert(alert)
            return alert
        return None

    def _create_alert(self, alert_type: str, rule: Dict, event_data: Dict) -> Optional[SecurityAlert]:
        """
        Create a SecurityAlert object from database event data.
        
        Args:
            alert_type: Type of alert
            rule: Alert rule configuration
            event_data: Raw event data from database
            
        Returns:
            Configured SecurityAlert object
        """
        try:
            # Extract timestamp from event data
            timestamp = event_data.get('ts', datetime.now().timestamp())
            if isinstance(timestamp, float):
                timestamp_dt = zeek_to_datetime(timestamp)
            else:
                timestamp_dt = datetime.now()
            
            # Extract relevant fields
            source_ip = event_data.get('id.orig_h') or event_data.get('source_ip')
            dest_ip = event_data.get('id.resp_h')
            port = event_data.get('id.resp_p')
            protocol = event_data.get('proto')
            
            return SecurityAlert(
                alert_id=self._generate_alert_id(),
                timestamp=timestamp_dt,
                severity=rule.get('severity', 'medium'),
                category=alert_type,
                description=self._generate_description(alert_type, event_data),
                source_ip=source_ip,
                dest_ip=dest_ip,
                port=port,
                protocol=protocol,
                evidence=event_data
            )
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            return None

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        from uuid import uuid4
        return f"alert-{datetime.now().strftime('%Y%m%d')}-{uuid4().hex[:6]}"

    def _generate_description(self, alert_type: str, event_data: Dict) -> str:
        """
        Generate human-readable alert description.
        
        Args:
            alert_type: Type of alert
            event_data: Raw event data from database
            
        Returns:
            Formatted description string
        """
        if alert_type == 'port_scan':
            return (
                f"Port scan detected from {event_data.get('source_ip', 'unknown')}. "
                f"Scanned {event_data.get('port_count', 0)} distinct ports between "
                f"{zeek_to_datetime(event_data.get('first_scan', 0))} and "
                f"{zeek_to_datetime(event_data.get('last_scan', 0))}"
            )
        elif alert_type == 'long_connection':
            return (
                f"Long connection ({event_data.get('duration', 0):.2f}s) between "
                f"{event_data.get('id.orig_h', 'unknown')} and "
                f"{event_data.get('id.resp_h', 'unknown')} "
                f"on port {event_data.get('id.resp_p', 'unknown')}"
            )
        elif alert_type == 'unusual_port':
            return (
                f"Connection to unusual port {event_data.get('id.resp_p', 'unknown')} "
                f"from {event_data.get('id.orig_h', 'unknown')} "
                f"to {event_data.get('id.resp_h', 'unknown')}"
            )
        elif alert_type == 'dns_tunneling':
            return (
                f"Potential DNS tunneling from {event_data.get('source_ip', 'unknown')}. "
                f"Long query: {event_data.get('query', '')[:50]}... "
                f"({event_data.get('query_length', 0)} chars, "
                f"{event_data.get('request_count', 0)} requests)"
            )
        else:
            return f"{alert_type.replace('_', ' ').title()} alert detected"

    # ... (The rest of the class remains similar to the previous implementation)
    # _notify, _log_alert, get_alerts, update_alert_status, export_alerts, etc.
    # would be the same as in the previous implementation

    def close(self):
        """Close database connection"""
        if hasattr(self, 'db_conn') and self.db_conn:
            self.db_conn.close()
            logger.info("Database connection closed")

    def __del__(self):
        self.close()