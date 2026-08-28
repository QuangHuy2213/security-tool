from datetime import datetime
from typing import Optional

class SecurityService:
    def __init__(self):
        self.total_requests = 0
        self.total_attacks = 0
        self.total_blocked = 0
        self.total_critical = 0
        self.events = []

    def record_request(self, ip_address: str, method: str, path: str):
        self.total_requests += 1
        print(f"[REQUEST #{self.total_requests}] {ip_address} {method} {path}")

    def record_attack(
        self,
        ip_address: str,
        method: str,
        path: str,
        attack_type: str,
        risk_score: int,
        action: str,
        reason: Optional[str] = None
    ):
        self.total_attacks += 1

        if action == "BLOCK":
            self.total_blocked += 1

        if risk_score >= 90:
            self.total_critical += 1

        event = {
            "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "ip_address": ip_address,
            "method": method,
            "path": path,
            "attack_type": attack_type,
            "risk_score": risk_score,
            "action": action,
            "reason": reason
        }

        self.events.insert(0, event)
        self.events = self.events[:200]

        print(
            f"[PHÁT HIỆN] {attack_type} | "
            f"IP: {ip_address} | Risk: {risk_score} | Action: {action}"
        )

    def get_stats(self):
        return {
            "requests": self.total_requests,
            "attacks": self.total_attacks,
            "blocked": self.total_blocked,
            "critical": self.total_critical
        }

    def get_events(self):
        return self.events

    def get_attack_statistics(self):
        statistics = {}

        for event in self.events:
            attack_type = event["attack_type"]

            if attack_type not in statistics:
                statistics[attack_type] = {
                    "attack_type": attack_type,
                    "count": 0,
                    "blocked": 0,
                    "average_risk": 0,
                    "total_risk": 0
                }

            statistics[attack_type]["count"] += 1
            statistics[attack_type]["total_risk"] += event["risk_score"]

            if event["action"] == "BLOCK":
                statistics[attack_type]["blocked"] += 1

        result = []

        for item in statistics.values():
            item["average_risk"] = round(
                item["total_risk"] / item["count"], 1
            )
            del item["total_risk"]
            result.append(item)

        result.sort(key=lambda x: x["count"], reverse=True)
        return result

security_service = SecurityService()