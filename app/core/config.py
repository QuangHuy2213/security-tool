import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    APP_NAME = os.getenv(
        "APP_NAME",
        "Hệ thống giám sát bảo mật website bất động sản",
    )

    APP_ENV = os.getenv(
        "APP_ENV",
        "development",
    )

    BACKEND_URL = os.getenv(
        "BACKEND_URL",
        "https://quanghuy-backend.onrender.com",
    )

    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "",
    )

    # =====================================================
    # SECURITY GATEWAY
    # =====================================================

    GATEWAY_SECRET = os.getenv(
        "GATEWAY_SECRET",
        "",
    )

    # =====================================================
    # BLOCK IP / CLIENT
    # =====================================================

    MAX_VIOLATIONS = int(
        os.getenv(
            "MAX_VIOLATIONS",
            "3",
        )
    )

    IMMEDIATE_BLOCK_SCORE = int(
        os.getenv(
            "IMMEDIATE_BLOCK_SCORE",
            "95",
        )
    )

    BLOCK_DURATION_SECONDS = int(
        os.getenv(
            "BLOCK_DURATION_SECONDS",
            "3600",
        )
    )

    # =====================================================
    # RATE LIMIT / API ABUSE
    # =====================================================

    RATE_LIMIT_REQUESTS = int(
        os.getenv(
            "RATE_LIMIT_REQUESTS",
            "60",
        )
    )

    RATE_LIMIT_WINDOW_SECONDS = int(
        os.getenv(
            "RATE_LIMIT_WINDOW_SECONDS",
            "60",
        )
    )

    RATE_LIMIT_RISK_SCORE = int(
        os.getenv(
            "RATE_LIMIT_RISK_SCORE",
            "60",
        )
    )

    RATE_LIMIT_READ_REQUESTS = int(
        os.getenv("RATE_LIMIT_READ_REQUESTS", "120")
    )

    RATE_LIMIT_WRITE_REQUESTS = int(
        os.getenv("RATE_LIMIT_WRITE_REQUESTS", "30")
    )

    RATE_LIMIT_PAYMENT_REQUESTS = int(
        os.getenv("RATE_LIMIT_PAYMENT_REQUESTS", "10")
    )

    RATE_LIMIT_UPLOAD_REQUESTS = int(
        os.getenv("RATE_LIMIT_UPLOAD_REQUESTS", "10")
    )

    API_ABUSE_MAX_STRIKES = int(
        os.getenv("API_ABUSE_MAX_STRIKES", "3")
    )

    API_ABUSE_STRIKE_WINDOW_SECONDS = int(
        os.getenv("API_ABUSE_STRIKE_WINDOW_SECONDS", "600")
    )

    # =====================================================
    # BRUTE FORCE LOGIN
    # =====================================================

    BRUTE_FORCE_MAX_FAILURES = int(
        os.getenv(
            "BRUTE_FORCE_MAX_FAILURES",
            "5",
        )
    )

    BRUTE_FORCE_WINDOW_SECONDS = int(
        os.getenv(
            "BRUTE_FORCE_WINDOW_SECONDS",
            "600",
        )
    )

    BRUTE_FORCE_BLOCK_SECONDS = int(
        os.getenv(
            "BRUTE_FORCE_BLOCK_SECONDS",
            "900",
        )
    )

    BRUTE_FORCE_RISK_SCORE = int(
        os.getenv(
            "BRUTE_FORCE_RISK_SCORE",
            "85",
        )
    )


settings = Settings()
