"""Middleware for authentication, rate limiting, and security headers."""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, Optional

from fastapi import HTTPException, Request, Response, status
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .config import SECURITY_HEADERS, get_settings
from .exceptions import AuthenticationException, RateLimitException
import logging

logger = logging.getLogger(__name__)
settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add security headers
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting middleware."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.requests: Dict[str, list] = defaultdict(list)
        self.enabled = settings.rate_limit_enabled
        self.max_requests = settings.rate_limit_requests
        self.window_seconds = settings.rate_limit_window_seconds
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        # Skip rate limiting for health checks
        if request.url.path == "/api/health":
            return await call_next(request)
        
        # Get client identifier (IP address)
        client_ip = request.client.host if request.client else "unknown"
        
        # Clean old requests
        now = time.time()
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip]
            if now - req_time < self.window_seconds
        ]
        
        # Check rate limit
        if len(self.requests[client_ip]) >= self.max_requests:
            logger.warning(
                "rate_limit_exceeded",
                extra={
                    "client_ip": client_ip,
                    "path": request.url.path,
                    "limit": self.max_requests,
                    "window": self.window_seconds,
                }
            )
            raise RateLimitException(
                f"Rate limit exceeded: {self.max_requests} requests per {self.window_seconds} seconds",
                retry_after=self.window_seconds
            )
        
        # Record request
        self.requests[client_ip].append(now)
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(
            self.max_requests - len(self.requests[client_ip])
        )
        response.headers["X-RateLimit-Reset"] = str(
            int(now + self.window_seconds)
        )
        
        return response


class APIKeyMiddleware(BaseHTTPMiddleware):
    """API key authentication middleware."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.api_keys = set(settings.api_keys)
        self.enabled = bool(self.api_keys)
        self.header_name = settings.api_key_header
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        # Skip auth for health checks and docs
        skip_paths = {"/api/health", "/docs", "/openapi.json", "/redoc"}
        if request.url.path in skip_paths:
            return await call_next(request)
        
        # Check API key
        api_key = request.headers.get(self.header_name)
        
        if not api_key:
            logger.warning(
                "auth.missing_api_key",
                extra={
                    "path": request.url.path,
                    "client_ip": request.client.host if request.client else "unknown",
                }
            )
            raise AuthenticationException("API key required")
        
        if api_key not in self.api_keys:
            logger.warning(
                "auth.invalid_api_key",
                extra={
                    "path": request.url.path,
                    "client_ip": request.client.host if request.client else "unknown",
                }
            )
            raise AuthenticationException("Invalid API key")
        
        # Process request
        return await call_next(request)


def setup_middleware(app):
    """Configure all middleware for the application."""
    # Add in reverse order (last added is executed first)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(APIKeyMiddleware)
