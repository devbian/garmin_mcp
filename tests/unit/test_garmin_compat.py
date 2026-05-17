"""Unit tests for garmin.cn compatibility patching."""

import json

from unittest.mock import Mock, patch

import pytest

from garmin_mcp.garmin_compat import (
    _dumps_with_jwt_web,
    _loads_with_jwt_web,
    _login_cn_portal_first,
)


class TokenClient:
    """Minimal client stub for token persistence tests."""

    di_token = None
    di_refresh_token = None
    di_client_id = None
    jwt_web = None
    csrf_token = None

    @property
    def is_authenticated(self):
        return bool(self.di_token or self.jwt_web)


class TestGarminCnCompat:
    """Tests for garmin.cn login strategy selection."""

    def test_non_cn_delegates_to_upstream_login(self):
        """Non-CN accounts should keep the upstream login flow."""
        client = Mock()
        client.domain = "garmin.com"

        with patch("garmin_mcp.garmin_compat._ORIGINAL_CLIENT_LOGIN", return_value=(None, None)) as mock_login:
            result = _login_cn_portal_first(client, "user@example.com", "secret")

        assert result == (None, None)
        mock_login.assert_called_once_with(
            client,
            "user@example.com",
            "secret",
            prompt_mfa=None,
            return_on_mfa=False,
        )

    def test_cn_prefers_portal_requests_when_cffi_fails(self):
        """garmin.cn should avoid mobile strategies and fall through to portal requests."""
        client = Mock()
        client.domain = "garmin.cn"
        client._portal_web_login_cffi.side_effect = RuntimeError("cffi unavailable")
        client._portal_web_login_requests.return_value = None

        result = _login_cn_portal_first(client, "user@example.com", "secret")

        assert result == (None, None)
        client._portal_web_login_cffi.assert_called_once_with("user@example.com", "secret")
        client._portal_web_login_requests.assert_called_once_with("user@example.com", "secret")

    def test_cn_raises_rate_limit_if_all_strategies_rate_limited(self):
        """garmin.cn should surface 429s cleanly when every strategy is blocked."""
        from garminconnect.exceptions import GarminConnectTooManyRequestsError

        client = Mock()
        client.domain = "garmin.cn"
        client._portal_web_login_cffi.side_effect = GarminConnectTooManyRequestsError("429")
        client._portal_web_login_requests.side_effect = GarminConnectTooManyRequestsError("429")

        with pytest.raises(GarminConnectTooManyRequestsError):
            _login_cn_portal_first(client, "user@example.com", "secret")

    def test_dumps_persists_jwt_web_fallback_tokens(self):
        """JWT_WEB fallback tokens should be written alongside DI token fields."""
        client = Mock()
        client.jwt_web = "jwt-token"
        client.csrf_token = "csrf-token"
        client.cs.cookies = []

        with patch("garmin_mcp.garmin_compat._ORIGINAL_CLIENT_DUMPS", return_value='{"di_token": null}'):
            data = json.loads(_dumps_with_jwt_web(client))

        assert data["di_token"] is None
        assert data["jwt_web"] == "jwt-token"
        assert data["csrf_token"] == "csrf-token"

    def test_loads_restores_jwt_web_without_di_tokens(self):
        """Token restore should accept JWT_WEB-only auth from the CN portal flow."""
        client = TokenClient()
        tokenstore = json.dumps(
            {
                "di_token": None,
                "di_refresh_token": None,
                "di_client_id": None,
                "jwt_web": "jwt-token",
                "csrf_token": "csrf-token",
            }
        )

        _loads_with_jwt_web(client, tokenstore)

        assert client.jwt_web == "jwt-token"
        assert client.csrf_token == "csrf-token"
