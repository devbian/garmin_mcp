"""Tests for using upstream Garmin China-region authentication."""

from garminconnect import Garmin as UpstreamGarmin
from garminconnect.client import Client

from garmin_mcp.garmin_compat import Garmin


def test_garmin_uses_upstream_client():
    assert Garmin is UpstreamGarmin
    assert Client.login.__module__ == "garminconnect.client"
    assert Client._run_request.__module__ == "garminconnect.client"


def test_cn_client_uses_cn_auth_host():
    client = Garmin(is_cn=True).client

    assert client.domain == "garmin.cn"
    assert client._mobile_sso_service_url == "https://mobile.integration.garmin.cn/gcm/android"
    assert client._di_token_url == "https://diauth.garmin.cn/di-oauth2-service/oauth/token"
