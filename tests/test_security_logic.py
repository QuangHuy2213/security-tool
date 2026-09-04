import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.gateway.proxy import (
    analyze_request,
    build_rate_limited_response,
    get_client_key,
)
from app.prevention.rate_limiter import get_rate_limit_group


class SecurityLogicTests(unittest.TestCase):
    def test_rate_limit_groups_are_endpoint_specific(self):
        self.assertEqual(get_rate_limit_group("GET", "/api/posts")[0], "read")
        self.assertEqual(get_rate_limit_group("POST", "/api/posts")[0], "write")
        self.assertEqual(get_rate_limit_group("POST", "/api/payments")[0], "payment")
        self.assertEqual(get_rate_limit_group("POST", "/api/upload")[0], "upload")

    def test_client_id_is_primary_identity(self):
        headers = {"x-client-id": "browser-1", "user-agent": "ua"}
        request = SimpleNamespace(headers=headers)
        self.assertEqual(
            get_client_key(request, "10.0.0.1"),
            get_client_key(request, "10.0.0.2"),
        )

    def test_fallback_identity_separates_users_behind_nat(self):
        first = SimpleNamespace(headers={"user-agent": "browser-a"})
        second = SimpleNamespace(headers={"user-agent": "browser-b"})
        self.assertNotEqual(
            get_client_key(first, "10.0.0.1"),
            get_client_key(second, "10.0.0.1"),
        )

    def test_sqli_and_xss_remain_blocking_detections(self):
        self.assertEqual(analyze_request("' OR 1=1--")["attack_type"], "SQL Injection")
        self.assertEqual(
            analyze_request("<script>alert(1)</script>")["attack_type"],
            "Cross-Site Scripting (XSS)",
        )

    def test_followup_429_does_not_create_event_or_violation(self):
        rate_result = {
            "allowed": False, "count": 122, "limit": 120,
            "group": "read", "retry_after": 30, "new_burst": False,
        }
        with patch("app.gateway.proxy.security_service.record_attack", new=AsyncMock()) as event, \
             patch("app.gateway.proxy.ip_blocker.register_violation", new=AsyncMock()) as violation:
            response = asyncio.run(build_rate_limited_response(
                rate_result=rate_result, client_ip="127.0.0.1", client_key="key",
                user_agent="test", method="GET", request_path="/api/posts",
            ))
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["retry-after"], "30")
        event.assert_not_awaited()
        violation.assert_not_awaited()

    def test_third_independent_burst_escalates_once(self):
        rate_result = {
            "allowed": False, "count": 121, "limit": 120,
            "group": "read", "retry_after": 30, "new_burst": True,
        }
        abuse = AsyncMock(return_value={"strikes": 3, "max_strikes": 3, "escalated": True})
        violation = AsyncMock(return_value={"violation_count": 1, "total_risk": 60})
        block = AsyncMock()
        event = AsyncMock()
        with patch("app.gateway.proxy.rate_limiter.register_abuse_strike", new=abuse), \
             patch("app.gateway.proxy.security_service.record_attack", new=event), \
             patch("app.gateway.proxy.ip_blocker.register_violation", new=violation), \
             patch("app.gateway.proxy.ip_blocker.block_ip", new=block):
            response = asyncio.run(build_rate_limited_response(
                rate_result=rate_result, client_ip="127.0.0.1", client_key="key",
                user_agent="test", method="GET", request_path="/api/posts",
            ))
        self.assertEqual(response.status_code, 429)
        abuse.assert_awaited_once()
        event.assert_awaited_once()
        violation.assert_awaited_once()
        block.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
