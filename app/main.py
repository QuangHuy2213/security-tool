from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import text

from app.core.config import settings
from app.routes.dashboard import router as dashboard_router
from app.gateway.proxy import router as proxy_router
from app.database.database import AsyncSessionLocal


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Công cụ phát hiện, cảnh báo và ngăn chặn "
        "các hành vi tấn công trên website bất động sản"
    ),
    version="1.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://nguyenducquanghuy.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# STATIC FILES
# =========================================================

app.mount(
    "/static",
    StaticFiles(
        directory="app/static"
    ),
    name="static",
)


# =========================================================
# ROUTERS
# =========================================================

# Dashboard
app.include_router(
    dashboard_router
)

# Security Gateway
app.include_router(
    proxy_router
)


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
async def health_check():
    return {
        "trang_thai": "hoat_dong",
        "dich_vu": settings.APP_NAME,
        "moi_truong": settings.APP_ENV,
    }


# =========================================================
# DEVELOPMENT TEST ROUTES
# Chỉ mở khi không phải production
# =========================================================

if settings.APP_ENV != "production":

    @app.get("/test-database")
    async def test_database():
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    text("SELECT NOW()")
                )

                current_time = result.scalar()

            return {
                "status": "success",
                "message": "Kết nối PostgreSQL thành công",
                "database_time": str(current_time),
            }

        except Exception as exc:
            return {
                "status": "error",
                "message": "Không thể kết nối PostgreSQL",
                "error": str(exc),
            }


    @app.get("/test-security-tables")
    async def test_security_tables():
        try:
            async with AsyncSessionLocal() as db:

                security_events = await db.execute(
                    text(
                        "SELECT COUNT(*) "
                        "FROM security_events"
                    )
                )

                client_violations = await db.execute(
                    text(
                        "SELECT COUNT(*) "
                        "FROM security_client_violations"
                    )
                )

                blocked_ips = await db.execute(
                    text(
                        "SELECT COUNT(*) "
                        "FROM security_blocked_ips"
                    )
                )

                rate_limits = await db.execute(
                    text(
                        "SELECT COUNT(*) "
                        "FROM security_rate_limits"
                    )
                )

                login_attempts = await db.execute(
                    text(
                        "SELECT COUNT(*) "
                        "FROM security_login_attempts"
                    )
                )

            return {
                "status": "success",
                "security_events": (
                    security_events.scalar()
                ),
                "security_client_violations": (
                    client_violations.scalar()
                ),
                "security_blocked_ips": (
                    blocked_ips.scalar()
                ),
                "security_rate_limits": (
                    rate_limits.scalar()
                ),
                "security_login_attempts": (
                    login_attempts.scalar()
                ),
            }

        except Exception as exc:
            return {
                "status": "error",
                "message": (
                    "Không thể đọc các bảng security"
                ),
                "error": str(exc),
            }


    @app.get("/test-rate-config")
    async def test_rate_config():
        return {
            "RATE_LIMIT_REQUESTS":
                settings.RATE_LIMIT_REQUESTS,

            "RATE_LIMIT_WINDOW_SECONDS":
                settings.RATE_LIMIT_WINDOW_SECONDS,

            "RATE_LIMIT_RISK_SCORE":
                settings.RATE_LIMIT_RISK_SCORE,

            "BRUTE_FORCE_MAX_FAILURES":
                settings.BRUTE_FORCE_MAX_FAILURES,

            "BRUTE_FORCE_WINDOW_SECONDS":
                settings.BRUTE_FORCE_WINDOW_SECONDS,

            "BRUTE_FORCE_BLOCK_SECONDS":
                settings.BRUTE_FORCE_BLOCK_SECONDS,

            "BRUTE_FORCE_RISK_SCORE":
                settings.BRUTE_FORCE_RISK_SCORE,
        }