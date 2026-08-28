from datetime import datetime


class SecurityService:
    def __init__(self):
        self.total_requests = 0
        self.total_attacks = 0
        self.total_blocked = 0
        self.total_critical = 0

        self.events = []

    def record_request(
        self,
        ip_address: str,
        method: str,
        path: str,
    ):
        self.total_requests += 1

        print(
            f"[SECURITY] Request #{self.total_requests} "
            f"| {ip_address} "
            f"| {method} "
            f"| {path}"
        )

    def get_stats(self):
        return {
            "requests": self.total_requests,
            "attacks": self.total_attacks,
            "blocked": self.total_blocked,
            "critical": self.total_critical,
        }

    def get_events(self):
        return self.events


security_service = SecurityService()