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

        self.violations[ip_address]["count"] += 1
        self.violations[ip_address]["total_risk"] += risk_score
        self.violations[ip_address]["last_violation"] = datetime.now().strftime(
            "%d/%m/%Y %H:%M:%S"
        )

        count = self.violations[ip_address]["count"]

        print(
            f"[VI PHẠM] IP={ip_address} "
            f"| Lần={count} "
            f"| Risk={risk_score}"
        )

        should_block = risk_score >= 95 or count >= 3

        if should_block and not self.is_blocked(ip_address):
            reason = (
                f"Phát hiện {attack_type}. "
                f"Số lần vi phạm: {count}. "
                f"Risk Score gần nhất: {risk_score}/100."
            )

            self.block_ip(
                ip_address=ip_address,
                reason=reason
            )

        return {
            "violation_count": count,
            "blocked": self.is_blocked(ip_address)
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

        print(f"[KHÓA IP] {ip_address} | {reason}")

    def unblock_ip(self, ip_address: str):
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]

        if ip_address in self.violations:
            del self.violations[ip_address]

        print(f"[BỎ CHẶN IP] {ip_address}")

        return True

    def is_blocked(self, ip_address: str):
        return ip_address in self.blocked_ips

    def get_blocked_ip(self, ip_address: str):
        return self.blocked_ips.get(ip_address)

    def get_blocked_ips(self):
        return list(self.blocked_ips.values())

    def get_violation_count(self, ip_address: str):
        if ip_address not in self.violations:
            return 0

        return self.violations[ip_address]["count"]


ip_blocker = IPBlocker()