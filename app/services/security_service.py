from datetime import datetime
from typing import Optional


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
            f"[REQUEST #{self.total_requests}] "
            f"{ip_address} "
            f"{method} "
            f"{path}"
        )


    def record_attack(
        self,
        ip_address: str,
        method: str,
        path: str,
        attack_type: str,
        risk_score: int,
        action: str,
        reason: Optional[str] = None,
    ):

        self.total_attacks += 1

        if action == "BLOCK":
            self.total_blocked += 1

        if risk_score >= 90:
            self.total_critical += 1


        event = {
            "time": datetime.now().strftime(
                "%d/%m/%Y %H:%M:%S"
            ),

            "ip_address": ip_address,

            "method": method,

            "path": path,

            "attack_type": attack_type,

            "risk_score": risk_score,

            "action": action,

            "reason": reason,
        }


        # Đưa event mới lên đầu
        self.events.insert(
            0,
            event,
        )


        # Tạm thời chỉ giữ 100 event gần nhất
        self.events = self.events[:100]


        print(
            f"[PHÁT HIỆN] "
            f"{attack_type} "
            f"| IP: {ip_address} "
            f"| Risk: {risk_score} "
            f"| Action: {action}"
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