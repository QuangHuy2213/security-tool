import re
from typing import Dict, Any


XSS_PATTERNS = [
    r"<\s*script",
    r"<\s*/\s*script",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"<\s*iframe",
    r"<\s*object",
    r"<\s*embed",
    r"<\s*svg[^>]*on\w+\s*=",
]


def detect_xss(content: str) -> Dict[str, Any]:
    """
    Phát hiện các dấu hiệu Cross-Site Scripting cơ bản.
    """

    if not content:
        return {
            "detected": False,
            "score": 0,
            "matches": [],
        }

    matches = []

    for pattern in XSS_PATTERNS:
        if re.search(
            pattern,
            content,
            re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "score": 0,
            "matches": [],
        }

    score = min(
        85 + ((len(matches) - 1) * 3),
        100,
    )

    return {
        "detected": True,
        "score": score,
        "matches": matches,
    }