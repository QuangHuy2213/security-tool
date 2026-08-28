from datetime import datetime

class IPBlocker:
    def __init__(self):
        self.blocked_ips = {}
        self.violations = {}

    def register_violation(self, ip_address: str, risk_score: int, attack_type: str):
        if ip_address not in self.violations:
            self.violations[ip_address] = {
                "count": 0,
                "total_risk": 0,
                "last_violation": None
            }

        data = self.violations[ip_address]
        data["count"] += 1
        data["total_risk"] += risk_score
        data["last_violation"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        should_block = risk_score >= 95 or data["count"] >= 3

        if should_block:
            reason = (
                f"Phát hiện {attack_type}. "
                f"Số lần vi phạm: {data['count']}. "
                f"Risk Score gần nhất: {risk_score}/100."
            )
            self.block_ip(ip_address, reason)

        return {
            "violation_count": data["count"],
            "blocked": should_block
        }

    def block_ip(self, ip_address: str, reason: str):
        violation = self.violations.get(ip_address, {})

        self.blocked_ips[ip_address] = {
            "ip_address": ip_address,
            "reason": reason,
            "blocked_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "violation_count": violation.get("count", 0),
            "total_risk": violation.get("total_risk", 0)
        }

        print(f"[BLOCK IP] {ip_address} | {reason}")

    def unblock_ip(self, ip_address: str):
        removed = False

        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
            removed = True

        if ip_address in self.violations:
            del self.violations[ip_address]

        return removed

    def is_blocked(self, ip_address: str):
        return ip_address in self.blocked_ips

    def get_blocked_ip(self, ip_address: str):
        return self.blocked_ips.get(ip_address)

    def get_blocked_ips(self):
        return list(self.blocked_ips.values())

    def get_violation_count(self, ip_address: str):
        return self.violations.get(ip_address, {}).get("count", 0)

ip_blocker = IPBlocker()