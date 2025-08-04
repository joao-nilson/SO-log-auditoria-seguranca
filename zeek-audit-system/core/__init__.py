"""
Core processing components for the Zeek Security Audit System.

Exposes:
- LogProcessor: Main log processing functionality
- SecurityAnalyzer: Anomaly detection engine
- AlertManager: Alert generation and handling
"""

from .processor import LogProcessor
from .analyzer import SecurityAnalyzer
from .alerts import AlertManager

__all__ = ['LogProcessor', 'SecurityAnalyzer', 'AlertManager']