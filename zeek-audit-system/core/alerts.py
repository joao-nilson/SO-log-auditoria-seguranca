from typing import List, Dict, Optional
import sqlite3
import yaml
from pathlib import Path
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SecurityAlert:
    """Data class representing a security alert"""
    def __init__(self, alert_id: str, timestamp: datetime, severity: str, category: str,
                 description: str, source_ip: Optional[str] = None, dest_ip: Optional[str] = None,
                 port: Optional[int] = None, protocol: Optional[str] = None,
                 evidence: Optional[Dict] = None, status: str = 'open'):
        self.alert_id = alert_id
        self.timestamp = timestamp
        self.severity = severity
        self.category = category
        self.description = description
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.port = port
        self.protocol = protocol
        self.evidence = evidence
        self.status = status

class BatchAlertManager:
    def __init__(self, db_path: str, config_path: str = 'config/alert_rules.yml'):
        """
        Initialize the Batch Alert Manager
        
        Args:
            db_path: Path to SQLite database file
            config_path: Path to alert rules configuration file
        """
        self.db_path = db_path
        self.config_path = config_path
        self.alerts: List[SecurityAlert] = []
        self.load_rules(config_path)
        self._setup_notification_channels()

    def load_rules(self, config_path: str) -> None:
        """Load alert rules from YAML configuration file"""
        try:
            with open(config_path, 'r') as f:
                self.rules = yaml.safe_load(f) or {}
            logger.info(f"Loaded {len(self.rules)} alert rules from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load alert rules: {e}")
            self.rules = {}

    def _setup_notification_channels(self) -> None:
        """Initialize notification channels"""
        self.notification_channels = ['log']  # Default to logging

    # Rest of your BatchAlertManager implementation...