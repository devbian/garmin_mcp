"""Garmin client import shared by the server and authentication helpers.

Recent garminconnect releases handle China-region authentication directly.
Do not monkey-patch their login or request flow: doing so bypasses upstream
token validation and domain-aware DI token exchange.
"""

from garminconnect import Garmin

__all__ = ["Garmin"]
