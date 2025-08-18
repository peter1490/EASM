"""Utility functions for the EASM application."""
from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable, Optional, TypeVar, Union

logger = logging.getLogger(__name__)

T = TypeVar('T')


async def retry_async(
    func: Callable[..., T],
    *args,
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    max_delay: float = 60.0,
    exceptions: tuple = (Exception,),
    **kwargs
) -> Optional[T]:
    """Retry an async function with exponential backoff.
    
    Args:
        func: The async function to retry
        max_attempts: Maximum number of attempts
        delay: Initial delay between retries in seconds
        backoff: Backoff multiplier
        max_delay: Maximum delay between retries
        exceptions: Tuple of exceptions to catch and retry
        
    Returns:
        The result of the function or None if all attempts failed
    """
    current_delay = delay
    last_exception = None
    
    for attempt in range(max_attempts):
        try:
            return await func(*args, **kwargs)
        except exceptions as e:
            last_exception = e
            if attempt < max_attempts - 1:
                logger.warning(
                    "retry_attempt_failed",
                    extra={
                        "function": func.__name__,
                        "attempt": attempt + 1,
                        "max_attempts": max_attempts,
                        "error": str(e),
                        "next_delay": current_delay,
                    }
                )
                await asyncio.sleep(current_delay)
                current_delay = min(current_delay * backoff, max_delay)
            else:
                logger.error(
                    "retry_exhausted",
                    extra={
                        "function": func.__name__,
                        "attempts": max_attempts,
                        "error": str(e),
                    }
                )
    
    return None


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    max_delay: float = 60.0,
    exceptions: tuple = (Exception,),
):
    """Decorator for retrying async functions with exponential backoff."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await retry_async(
                func,
                *args,
                max_attempts=max_attempts,
                delay=delay,
                backoff=backoff,
                max_delay=max_delay,
                exceptions=exceptions,
                **kwargs
            )
        return wrapper
    return decorator


class CircuitBreaker:
    """Simple circuit breaker implementation."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type = Exception,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "closed"  # closed, open, half-open
    
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function through circuit breaker."""
        if self.state == "open":
            if self.last_failure_time and \
               asyncio.get_event_loop().time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half-open"
                logger.info("circuit_breaker_half_open", extra={"function": func.__name__})
            else:
                raise Exception(f"Circuit breaker is open for {func.__name__}")
        
        try:
            result = await func(*args, **kwargs)
            if self.state == "half-open":
                self.state = "closed"
                self.failure_count = 0
                logger.info("circuit_breaker_closed", extra={"function": func.__name__})
            return result
        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = asyncio.get_event_loop().time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.error(
                    "circuit_breaker_open",
                    extra={
                        "function": func.__name__,
                        "failures": self.failure_count,
                        "recovery_timeout": self.recovery_timeout,
                    }
                )
            raise


def chunk_list(lst: list, chunk_size: int) -> list[list]:
    """Split a list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def truncate_string(s: str, max_length: int, suffix: str = "...") -> str:
    """Truncate a string to a maximum length with suffix."""
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def safe_get_nested(data: dict, *keys, default=None):
    """Safely get nested dictionary values."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
            if data is None:
                return default
        else:
            return default
    return data


def normalize_url(url: str) -> str:
    """Normalize a URL for consistency."""
    url = url.strip().lower()
    
    # Ensure protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove trailing slashes
    while url.endswith('/'):
        url = url[:-1]
    
    return url


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


async def run_with_timeout(
    coro,
    timeout: float,
    timeout_msg: Optional[str] = None
) -> Any:
    """Run a coroutine with a timeout."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        msg = timeout_msg or f"Operation timed out after {timeout} seconds"
        logger.warning("operation_timeout", extra={"timeout": timeout})
        raise TimeoutError(msg)
