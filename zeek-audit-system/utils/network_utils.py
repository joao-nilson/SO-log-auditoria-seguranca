"""
Network-related utilities for Zeek log processing.
Handles IP addresses, ports, and network analysis.
"""

from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
import socket
from typing import Union, Optional

def is_internal_ip(ip: str) -> bool:
    """
    Check if an IP address is in internal/reserved ranges.
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is in private/reserved ranges
    """
    try:
        addr = ip_address(ip)
        return (
            addr.is_private or 
            addr.is_loopback or 
            addr.is_link_local or 
            addr.is_reserved
        )
    except ValueError:
        return False

def port_to_service(port: int, proto: str = 'tcp') -> str:
    """
    Convert port number to service name.
    
    Args:
        port: Port number
        proto: Protocol ('tcp' or 'udp')
        
    Returns:
        Service name if known, else str(port)
    """
    try:
        return socket.getservbyport(port, proto)
    except (socket.error, OverflowError):
        return str(port)

def is_common_port(port: int) -> bool:
    """
    Check if port is in list of commonly used ports.
    
    Args:
        port: Port number to check
        
    Returns:
        True if port is in common services list
    """
    common_ports = {
        20, 21, 22, 23, 25, 53, 80, 110, 143, 
        443, 465, 587, 993, 995, 3306, 3389
    }
    return port in common_ports

def resolve_ip(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup for an IP address.
    
    Args:
        ip: IP address to resolve
        
    Returns:
        Hostname if resolvable, None otherwise
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def validate_ip_address(ip: str) -> bool:
    """
    Validate if string is a valid IP address.
    
    Args:
        ip: String to validate
        
    Returns:
        True if valid IPv4 or IPv6 address
    """
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

def cidr_contains_ip(cidr: str, ip: str) -> bool:
    """
    Check if IP address falls within a CIDR range.

    Args:
        cidr: CIDR notation (e.g., '192.168.1.0/24')
        ip: IP address to check

    Returns:
        True if IP is within CIDR range
    """
    try:
        network = ip_network(cidr, strict=False)
        ip_addr = ip_address(ip)
        return ip_addr in network
    except (ValueError, IndexError):
        return False

def is_suspicious_port(port: int) -> bool:
    """
    Check if port is commonly associated with malicious activity.
    
    Args:
        port: Port number to check
        
    Returns:
        True if port is suspicious
    """
    suspicious_ports = {
        4444, 5555, 6666, 7777, 8888,  # Common malware ports
        31337,  # Elite/Back Orifice
        12345, 12346,  # NetBus
        27374,  # Sub7
        54321   # Back Construction
    }
    return port in suspicious_ports