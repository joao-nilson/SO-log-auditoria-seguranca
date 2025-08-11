"""
Log formatting utilities for Zeek log processing.
Handles conversion between raw logs and human-readable formats.
"""

from ipaddress import ip_address
import json
from datetime import datetime

def format_connection_log(conn_log: dict) -> str:
    """
    Format a connection log entry into human-readable string.
    
    Args:
        conn_log: Raw Zeek connection log entry
        
    Returns:
        Formatted string with key connection details
    """
    return (
        f"Connection {conn_log.get('uid', 'N/A')}: "
        f"{conn_log.get('id_orig_h', '?')}:{conn_log.get('id_orig_p', '?')} → "
        f"{conn_log.get('id_resp_h', '?')}:{conn_log.get('id_resp_p', '?')} "
        f"Proto: {conn_log.get('proto', 'N/A')} "
        f"Duration: {conn_log.get('duration', 0):.2f}s "
        f"Bytes: {conn_log.get('orig_bytes', 0)}/{conn_log.get('resp_bytes', 0)}"
    )

def format_http_log(http_log: dict) -> str:
    """
    Format HTTP log entry for display.
    
    Args:
        http_log: Raw Zeek HTTP log entry
        
    Returns:
        Formatted string with key HTTP details
    """
    return (
        f"HTTP {http_log.get('uid', 'N/A')}: "
        f"{http_log.get('host', 'N/A')} "
        f"{http_log.get('method', 'N/A')} {http_log.get('uri', 'N/A')} "
        f"Status: {http_log.get('status_code', 'N/A')} "
        f"User-Agent: {http_log.get('user_agent', 'N/A')[:50]}"
    )

def anonymize_ip(ip: str, level: int = 2) -> str:
    """
    Anonymize IP address based on specified level.
    
    Args:
        ip: Original IP address
        level: Anonymization level (1=partial, 2=full, 3=crypto hash)
        
    Returns:
        Anonymized IP string
    """
    try:
        if not ip or ip in ('0.0.0.0', '::'):
            return ip
            
        addr = ip_address(ip)
        
        if level == 1:  # Partial anonymization (last octet)
            if addr.version == 4:
                return '.'.join(ip.split('.')[:-1] + ['xxx'])
            else:
                return ':'.join(ip.split(':')[:-1] + ['xxxx'])
        elif level == 2:  # Full anonymization
            return 'xxx.xxx.xxx.xxx' if addr.version == 4 else 'xxxx:xxxx::'
        elif level == 3:  # Cryptographic hashing
            import hashlib
            return hashlib.sha256(ip.encode()).hexdigest()[:16]
        return ip
    except ValueError:
        return ip

def log_to_json(log_entry: dict) -> str:
    """
    Convert log entry to pretty-printed JSON string.
    
    Args:
        log_entry: Raw log dictionary
        
    Returns:
        Formatted JSON string
    """
    return json.dumps(log_entry, indent=2, default=str)

def format_dns_log(dns_log: dict) -> str:
    """
    Format DNS log entry for display.
    
    Args:
        dns_log: Raw Zeek DNS log entry
        
    Returns:
        Formatted string with key DNS details
    """
    return (
        f"DNS {dns_log.get('uid', 'N/A')}: "
        f"Query: {dns_log.get('query', 'N/A')} "
        f"Type: {dns_log.get('qtype_name', 'N/A')} "
        f"Answers: {', '.join(dns_log.get('answers', []))[:50]}"
    )