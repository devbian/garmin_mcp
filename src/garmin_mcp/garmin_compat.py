"""Compatibility helpers for garminconnect behavior used by this project."""

from __future__ import annotations

from typing import Any

from garminconnect import Garmin
from garminconnect.client import Client
from garminconnect.client import _MFARequired
from garminconnect.exceptions import (
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)


_ORIGINAL_CLIENT_LOGIN = Client.login
_ORIGINAL_CLIENT_DUMPS = Client.dumps
_ORIGINAL_CLIENT_LOADS = Client.loads
_ORIGINAL_CLIENT_RUN_REQUEST = Client._run_request
_PATCH_APPLIED = False


def _login_cn_portal_first(
    self: Client,
    email: str,
    password: str,
    prompt_mfa: Any = None,
    return_on_mfa: bool = False,
) -> tuple[str | None, Any]:
    """Prefer portal login strategies for garmin.cn accounts.

    The upstream strategy chain tries international mobile endpoints first.
    For `garmin.cn`, those endpoints are not a reliable fit and can fail before
    the portal flow has a chance to establish a usable JWT_WEB session.
    """
    if self.domain != "garmin.cn":
        return _ORIGINAL_CLIENT_LOGIN(
            self,
            email,
            password,
            prompt_mfa=prompt_mfa,
            return_on_mfa=return_on_mfa,
        )

    strategies: list[tuple[str, Any]] = [
        ("portal+cffi", lambda: self._portal_web_login_cffi(email, password)),
        ("portal+requests", lambda: self._portal_web_login_requests(email, password)),
    ]

    last_err: Exception | None = None
    rate_limited_count = 0

    for name, run in strategies:
        try:
            run()
            return None, None
        except GarminConnectAuthenticationError:
            raise
        except _MFARequired:
            if return_on_mfa:
                return "needs_mfa", None
            if prompt_mfa:
                mfa_code = prompt_mfa()
                self._complete_mfa(mfa_code)
                return None, None
            raise GarminConnectAuthenticationError(
                "MFA Required but no prompt_mfa mechanism supplied"
            )
        except GarminConnectTooManyRequestsError as e:
            rate_limited_count += 1
            last_err = e
            continue
        except Exception as e:
            last_err = e
            continue

    if rate_limited_count == len(strategies):
        raise GarminConnectTooManyRequestsError(
            "All CN login strategies rate limited (429). Try again later."
        )
    raise GarminConnectConnectionError(f"All CN login strategies exhausted: {last_err}")


def ensure_garmin_cn_compat() -> None:
    """Patch garminconnect once for garmin.cn login compatibility."""
    global _PATCH_APPLIED

    if _PATCH_APPLIED:
        return

    Client.login = _login_cn_portal_first
    Client.dumps = _dumps_with_jwt_web
    Client.loads = _loads_with_jwt_web
    Client._run_request = _run_request_with_cn_gc_api
    _PATCH_APPLIED = True


def _dumps_with_jwt_web(self: Client) -> str:
    """Persist fallback JWT_WEB auth state in addition to DI tokens."""
    import json

    cookies = getattr(getattr(self, "cs", None), "cookies", [])
    cookie_iter = getattr(cookies, "jar", cookies)
    data = json.loads(_ORIGINAL_CLIENT_DUMPS(self))
    data.update(
        {
            "jwt_web": getattr(self, "jwt_web", None),
            "csrf_token": getattr(self, "csrf_token", None),
            "cookies": [
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "expires": cookie.expires,
                }
                for cookie in cookie_iter
                if hasattr(cookie, "name")
            ],
        }
    )
    return json.dumps(data)


def _loads_with_jwt_web(self: Client, tokenstore: str) -> None:
    """Restore fallback JWT_WEB auth state when DI tokens are unavailable."""
    import json

    data = json.loads(tokenstore)
    if data.get("di_token") or data.get("di_refresh_token"):
        _ORIGINAL_CLIENT_LOADS(self, tokenstore)
    else:
        self.di_token = None
        self.di_refresh_token = None
        self.di_client_id = data.get("di_client_id")
    self.jwt_web = data.get("jwt_web")
    self.csrf_token = data.get("csrf_token")
    for cookie in data.get("cookies") or []:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        self.cs.cookies.set(
            name,
            value,
            domain=cookie.get("domain"),
            path=cookie.get("path") or "/",
        )
    if not self.is_authenticated:
        raise GarminConnectConnectionError("Missing tokens from dict load")


def _run_request_with_cn_gc_api(self: Client, method: str, path: str, **kwargs: Any) -> Any:
    """Route garmin.cn JWT_WEB sessions through the web gc-api gateway."""
    if self.domain != "garmin.cn" or self.di_token:
        return _ORIGINAL_CLIENT_RUN_REQUEST(self, method, path, **kwargs)

    if not self.is_authenticated:
        raise GarminConnectAuthenticationError("Not authenticated")

    import requests

    url = f"https://connect.garmin.cn/gc-api/{path.lstrip('/')}"
    if "timeout" not in kwargs:
        kwargs["timeout"] = 15

    if not self.csrf_token:
        _load_cn_csrf_token(self)

    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Referer": "https://connect.garmin.cn/modern/",
        "Origin": "https://connect.garmin.cn",
        "NK": "NT",
        "X-Requested-With": "XMLHttpRequest",
    }
    if self.csrf_token:
        headers["Connect-Csrf-Token"] = str(self.csrf_token)

    custom_headers = kwargs.pop("headers", {})
    headers.update(custom_headers)

    resp = self.cs.request(method, url, headers=headers, **kwargs)
    if resp.status_code >= 400:
        error_msg = f"API Error {resp.status_code}"
        try:
            error_data = resp.json()
            if isinstance(error_data, dict):
                msg = error_data.get("message") or error_data.get("error")
                if msg:
                    error_msg += f" - {msg}"
        except Exception:
            if len(resp.text) < 500:
                error_msg += f" - {resp.text}"
        raise GarminConnectConnectionError(error_msg)

    return resp


def _load_cn_csrf_token(self: Client) -> None:
    """Fetch the Garmin CN shell page to populate the web CSRF token."""
    import re

    resp = self.cs.get(
        "https://connect.garmin.cn/modern/",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            )
        },
        timeout=15,
    )
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', resp.text)
    if match:
        self.csrf_token = match.group(1)


ensure_garmin_cn_compat()

__all__ = ["Garmin", "ensure_garmin_cn_compat"]
