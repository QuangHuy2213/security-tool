from fastapi import (
    APIRouter,
    Request,
)

from fastapi.responses import (
    RedirectResponse,
)

from fastapi.templating import (
    Jinja2Templates,
)

from app.core.config import settings

from app.services.security_service import (
    security_service,
)

from app.prevention.ip_blocker import (
    ip_blocker,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates"
)


# =========================================================
# DASHBOARD
# =========================================================

@router.get("/")
async def dashboard(
    request: Request
):
    stats = (
        await security_service
        .get_stats()
    )

    events = (
        await security_service
        .get_events(
            limit=10
        )
    )

    blocked = (
        await ip_blocker
        .get_blocked_ips()
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "stats": stats,
            "events": events,
            "blocked_ips": blocked,
        },
        headers={
            "Cache-Control":
                "no-store, no-cache, must-revalidate"
        },
    )


# =========================================================
# SECURITY EVENTS
# =========================================================

@router.get(
    "/su-kien-bao-mat"
)
async def security_events(
    request: Request
):
    events = (
        await security_service
        .get_events()
    )

    stats = (
        await security_service
        .get_stats()
    )

    return templates.TemplateResponse(
        request=request,
        name="security_events.html",
        context={
            "events": events,
            "stats": stats,
        },
        headers={
            "Cache-Control": "no-store"
        },
    )


# =========================================================
# ATTACK STATISTICS
# =========================================================

@router.get(
    "/thong-ke-tan-cong"
)
async def attack_statistics(
    request: Request
):
    statistics = (
        await security_service
        .get_attack_statistics()
    )

    stats = (
        await security_service
        .get_stats()
    )

    return templates.TemplateResponse(
        request=request,
        name="attack_statistics.html",
        context={
            "statistics": statistics,
            "stats": stats,
        },
        headers={
            "Cache-Control": "no-store"
        },
    )


# =========================================================
# BLOCKED CLIENTS
# =========================================================

@router.get(
    "/ip-bi-chan"
)
async def blocked_ips(
    request: Request
):
    blocked = (
        await ip_blocker
        .get_blocked_ips()
    )

    stats = (
        await security_service
        .get_stats()
    )

    return templates.TemplateResponse(
        request=request,
        name="blocked_ips.html",
        context={
            "blocked_ips": blocked,
            "stats": stats,
        },
        headers={
            "Cache-Control": "no-store"
        },
    )


# =========================================================
# UNBLOCK BY IP
# =========================================================

@router.post(
    "/ip-bi-chan/{ip_address}/bo-chan"
)
async def unblock_ip(
    ip_address: str
):
    await ip_blocker.unblock_ip(
        ip_address
    )

    return RedirectResponse(
        url="/ip-bi-chan",
        status_code=303,
    )


# =========================================================
# UNBLOCK BY CLIENT KEY
# =========================================================

@router.post(
    "/client-bi-chan/{client_key}/bo-chan"
)
async def unblock_client(
    client_key: str
):
    await ip_blocker.unblock_client(
        client_key
    )

    return RedirectResponse(
        url="/ip-bi-chan",
        status_code=303,
    )


# =========================================================
# SECURITY RULES
# =========================================================

@router.get(
    "/quy-tac-bao-mat"
)
async def security_rules(
    request: Request
):
    rules = [
        {
            "name": "SQL Injection Detection",
            "code": "SQL_INJECTION",
            "category": "SQL Injection",
            "description": (
                "Phân tích path, query string và "
                "request body để phát hiện mẫu SQL Injection."
            ),
            "threshold": (
                "Risk Score ≥ 80"
            ),
            "risk_score": "90+",
            "action": "BLOCK",
            "http_status": "403",
            "status": True,
        },
        {
            "name": "Cross-Site Scripting Detection",
            "code": "XSS",
            "category": "XSS",
            "description": (
                "Phát hiện script, HTML nguy hiểm "
                "và payload có dấu hiệu Cross-Site Scripting."
            ),
            "threshold": (
                "Risk Score ≥ 80"
            ),
            "risk_score": "88+",
            "action": "BLOCK",
            "http_status": "403",
            "status": True,
        },
        {
            "name": "API Rate Limit",
            "code": "API_ABUSE",
            "category": "API Abuse",
            "description": (
                "Giới hạn số lượng request của cùng "
                "một client trong một khoảng thời gian."
            ),
            "threshold": (
                f"{settings.RATE_LIMIT_REQUESTS} request / "
                f"{settings.RATE_LIMIT_WINDOW_SECONDS} giây"
            ),
            "risk_score": (
                str(
                    settings
                    .RATE_LIMIT_RISK_SCORE
                )
            ),
            "action": "RATE LIMIT",
            "http_status": "429",
            "status": True,
        },
        {
            "name": "Login Brute Force Protection",
            "code": "BRUTE_FORCE",
            "category": "Brute Force",
            "description": (
                "Theo dõi số lần đăng nhập thất bại "
                "theo client và tài khoản."
            ),
            "threshold": (
                f"{settings.BRUTE_FORCE_MAX_FAILURES} "
                f"lần / "
                f"{settings.BRUTE_FORCE_WINDOW_SECONDS} giây"
            ),
            "risk_score": (
                str(
                    settings
                    .BRUTE_FORCE_RISK_SCORE
                )
            ),
            "action": "TEMP BLOCK",
            "http_status": "429",
            "status": True,
        },
        {
            "name": "Client Auto Blocking",
            "code": "CLIENT_BLOCK",
            "category": "Client Protection",
            "description": (
                "Tự động khóa client khi vi phạm "
                "nhiều lần hoặc Risk Score quá cao."
            ),
            "threshold": (
                f"{settings.MAX_VIOLATIONS} vi phạm "
                f"hoặc Risk ≥ "
                f"{settings.IMMEDIATE_BLOCK_SCORE}"
            ),
            "risk_score": (
                str(
                    settings
                    .IMMEDIATE_BLOCK_SCORE
                )
            ),
            "action": "BLOCK CLIENT",
            "http_status": "403",
            "status": True,
        },
    ]

    return templates.TemplateResponse(
        request=request,
        name="security_rules.html",
        context={
            "rules": rules,
        },
        headers={
            "Cache-Control": "no-store"
        },
    )


# =========================================================
# SETTINGS
# =========================================================

@router.get(
    "/cai-dat"
)
async def security_settings(
    request: Request
):
    gateway_settings = [
        {
            "name": "MAX_VIOLATIONS",
            "label": "Số lần vi phạm tối đa",
            "value": settings.MAX_VIOLATIONS,
            "description": (
                "Client sẽ bị khóa khi số lần vi phạm "
                "đạt ngưỡng này."
            ),
        },
        {
            "name": "IMMEDIATE_BLOCK_SCORE",
            "label": "Risk Score khóa ngay",
            "value": (
                settings
                .IMMEDIATE_BLOCK_SCORE
            ),
            "description": (
                "Request có Risk Score đạt ngưỡng "
                "sẽ khiến client bị khóa ngay."
            ),
        },
        {
            "name": "BLOCK_DURATION_SECONDS",
            "label": "Thời gian khóa client",
            "value": (
                settings
                .BLOCK_DURATION_SECONDS
            ),
            "unit": "giây",
            "description": (
                "Khoảng thời gian client bị chặn "
                "sau khi kích hoạt rule."
            ),
        },
    ]

    rate_limit_settings = [
        {
            "name": "RATE_LIMIT_REQUESTS",
            "label": "Số request tối đa",
            "value": (
                settings
                .RATE_LIMIT_REQUESTS
            ),
        },
        {
            "name": "RATE_LIMIT_WINDOW_SECONDS",
            "label": "Cửa sổ Rate Limit",
            "value": (
                settings
                .RATE_LIMIT_WINDOW_SECONDS
            ),
            "unit": "giây",
        },
        {
            "name": "RATE_LIMIT_RISK_SCORE",
            "label": "Risk Score API Abuse",
            "value": (
                settings
                .RATE_LIMIT_RISK_SCORE
            ),
        },
    ]

    brute_force_settings = [
        {
            "name": "BRUTE_FORCE_MAX_FAILURES",
            "label": "Số lần login sai tối đa",
            "value": (
                settings
                .BRUTE_FORCE_MAX_FAILURES
            ),
        },
        {
            "name": "BRUTE_FORCE_WINDOW_SECONDS",
            "label": "Cửa sổ theo dõi",
            "value": (
                settings
                .BRUTE_FORCE_WINDOW_SECONDS
            ),
            "unit": "giây",
        },
        {
            "name": "BRUTE_FORCE_BLOCK_SECONDS",
            "label": "Thời gian khóa đăng nhập",
            "value": (
                settings
                .BRUTE_FORCE_BLOCK_SECONDS
            ),
            "unit": "giây",
        },
        {
            "name": "BRUTE_FORCE_RISK_SCORE",
            "label": "Risk Score Brute Force",
            "value": (
                settings
                .BRUTE_FORCE_RISK_SCORE
            ),
        },
    ]

    system_info = {
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "backend_url": settings.BACKEND_URL,
        "gateway_secret_configured": bool(
            settings.GATEWAY_SECRET
        ),
        "database_configured": bool(
            settings.DATABASE_URL
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "gateway_settings": (
                gateway_settings
            ),
            "rate_limit_settings": (
                rate_limit_settings
            ),
            "brute_force_settings": (
                brute_force_settings
            ),
            "system_info": (
                system_info
            ),
        },
        headers={
            "Cache-Control": "no-store"
        },
    )