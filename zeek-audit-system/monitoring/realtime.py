from pyzeek import log_subscribe
from core.alerts import AlertManager

class RealTimeMonitor:
    def __init__(self):
        self.alert_mgr = AlertManager()
        
    def start(self):
        log_subscribe("conn", self._handle_conn)
        log_subscribe("http", self._handle_http)
        
    def _handle_conn(self, conn):
        # Real-time connection analysis
        if conn['duration'] > alert_rules.long_connections.threshold:
            self.alert_mgr.trigger('long_connection', conn)