from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.services.security_service import security_service
from app.prevention.ip_blocker import ip_blocker

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/")
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "stats": security_service.get_stats(),
            "events": security_service.get_events()[:10]
        }
    )

@router.get("/su-kien-bao-mat")
async def security_events(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="security_events.html",
        context={
            "events": security_service.get_events(),
            "stats": security_service.get_stats()
        }
    )

@router.get("/thong-ke-tan-cong")
async def attack_statistics(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="attack_statistics.html",
        context={
            "statistics": security_service.get_attack_statistics(),
            "stats": security_service.get_stats()
        }
    )

@router.get("/ip-bi-chan")
async def blocked_ips(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="blocked_ips.html",
        context={
            "blocked_ips": ip_blocker.get_blocked_ips()
        }
    )

@router.post("/ip-bi-chan/{ip_address}/bo-chan")
async def unblock_ip(ip_address: str):
    ip_blocker.unblock_ip(ip_address)
    return RedirectResponse(
        url="/ip-bi-chan",
        status_code=303
    )