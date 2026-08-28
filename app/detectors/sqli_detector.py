import re
from typing import Dict, Any


SQLI_PATTERNS = [
    r"\bunion\s+select\b",
    r"\bselect\s+.+\s+from\b",
    r"\binsert\s+into\b",
    r"\bdelete\s+from\b",
    r"\bdrop\s+table\b",
    r"\bupdate\s+.+\s+set\b",
    r"\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
    r"\band\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
    r"--",
    r"/\*.*?\*/",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
]


def detect_sqli(content: str) -> Dict[str, Any]:
    """
    Phát hiện các dấu hiệu SQL Injection cơ bản.
    """

    if not content:
        return {
            "detected": False,
            "score": 0,
            "matches": [],
        }

    content_lower = content.lower()

    matches = []

    for pattern in SQLI_PATTERNS:
        if re.search(
            pattern,
            content_lower,
            re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "score": 0,
            "matches": [],
        }

    # SQL Injection được xem là rủi ro cao
    score = min(
        90 + ((len(matches) - 1) * 2),
        100,
    )

    return {
        "detected": True,
        "score": score,
        "matches": matches,
    }