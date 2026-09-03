from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.services.security_service import security_service
from app.prevention.ip_blocker import ip_blocker


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates"
)


@router.get("/")
async def dashboard(
    request: Request
):
    stats = await security_service.get_stats()

    events = await security_service.get_events(
        limit=10
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "stats": stats,
            "events": events
        }
    )


@router.get("/su-kien-bao-mat")
async def security_events(
    request: Request
):
    events = await security_service.get_events()

    stats = await security_service.get_stats()

    return templates.TemplateResponse(
        request=request,
        name="security_events.html",
        context={
            "events": events,
            "stats": stats
        }
    )


@router.get("/thong-ke-tan-cong")
async def attack_statistics(
    request: Request
):
    statistics = (
        await security_service
        .get_attack_statistics()
    )

    stats = await security_service.get_stats()

    return templates.TemplateResponse(
        request=request,
        name="attack_statistics.html",
        context={
            "statistics": statistics,
            "stats": stats
        }
    )


@router.get("/ip-bi-chan")
async def blocked_ips(
    request: Request
):
    blocked = await ip_blocker.get_blocked_ips()

    return templates.TemplateResponse(
        request=request,
        name="blocked_ips.html",
        context={
            "blocked_ips": blocked
        }
    )


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
        status_code=303
    )