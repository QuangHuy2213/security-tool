from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.routes.dashboard import router as dashboard_router
from app.gateway.proxy import router as proxy_router


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Công cụ phát hiện, cảnh báo và ngăn chặn "
        "các hành vi tấn công trên website chợ tốt"
    ),
    version="1.0.0",
)


# =========================
# STATIC
# =========================

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)


# =========================
# ROUTER
# =========================

# Dashboard
app.include_router(
    dashboard_router
)

# Security Gateway
app.include_router(
    proxy_router
)


# =========================
# HEALTH CHECK
# =========================

@app.get("/health")
async def health_check():

    return {
        "trang_thai": "hoat_dong",
        "dich_vu": settings.APP_NAME,
        "moi_truong": settings.APP_ENV,
        "backend": settings.BACKEND_URL,
    }