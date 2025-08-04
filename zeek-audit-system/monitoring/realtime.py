try:
    from pyzeek import log_subscribe
except ImportError:
    log_subscribe = None

from core.alerts import BatchAlertManager
import yaml
import os

class RealTimeMonitor:
    def __init__(self, db_path="logs/zeek.sqlite", config_path="config/alert_rules.yml"):
        self.alert_mgr = BatchAlertManager(db_path, config_path)
        self.rules = self._load_rules(config_path)

    def _load_rules(self, config_path):
        if not os.path.exists(config_path):
            return {}
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}

    def start(self):
        if log_subscribe is None:
            print("pyzeek não está instalado. Monitoramento em tempo real indisponível.")
            return
        log_subscribe("conn", self._handle_conn)
        log_subscribe("http", self._handle_http)

    def _handle_conn(self, conn):
        # Exemplo: alerta para conexões longas
        rule = self.rules.get("long_connection", {})
        threshold = rule.get("threshold", 3600)
        if conn.get("duration", 0) > threshold:
            self.alert_mgr._create_and_trigger_alert("long_connection", rule, conn)

    def _handle_http(self, http):
        # Exemplo: placeholder para análise HTTP em tempo real
        pass