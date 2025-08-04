"""
Time conversion utilities for Zeek log processing.
Handles conversion between Zeek timestamps and Python datetime objects.
"""

from datetime import datetime, timedelta
import pytz

def zeek_to_datetime(zeek_ts: float) -> datetime:
    """
    Convert Zeek timestamp (Unix epoch) to datetime object.
    
    Args:
        zeek_ts: Zeek timestamp (seconds since Unix epoch)
        
    Returns:
        Timezone-aware datetime object
    """
    return datetime.fromtimestamp(zeek_ts, tz=pytz.UTC)

def datetime_to_zeek(dt: datetime) -> float:
    """
    Convert datetime object to Zeek timestamp.
    
    Args:
        dt: Datetime object (naive or timezone-aware)
        
    Returns:
        Seconds since Unix epoch as float
    """
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.timestamp()

def human_readable_duration(seconds: float) -> str:
    """
    Convert duration in seconds to human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        String like "1h 23m 45s"
    """
    td = timedelta(seconds=seconds)
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s"

def zeek_time_range_to_human(start: float, end: float) -> str:
    """
    Convert Zeek time range to human-readable string.
    
    Args:
        start: Start timestamp
        end: End timestamp
        
    Returns:
        Formatted time range string
    """
    start_dt = zeek_to_datetime(start)
    end_dt = zeek_to_datetime(end)
    duration = human_readable_duration(end - start)
    return f"{start_dt} to {end_dt} ({duration})"

def is_within_time_window(
    event_time: float, 
    window_start: float, 
    window_seconds: int
) -> bool:
    """
    Check if a Zeek timestamp falls within a time window.
    
    Args:
        event_time: Event timestamp to check
        window_start: Window start timestamp
        window_seconds: Window duration in seconds
        
    Returns:
        True if event is within window
    """
    return window_start <= event_time <= (window_start + window_seconds)