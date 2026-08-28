from fastapi import (
    APIRouter,
    Request,
)

from fastapi.templating import (
    Jinja2Templates,
)

from app.services.security_service import (
    security_service,
)


router = APIRouter()


templates = Jinja2Templates(
    directory="app/templates"
)


@router.get("/")
async def dashboard(
    request: Request
):

    stats = (
        security_service.get_stats()
    )

    events = (
        security_service.get_events()
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "stats": stats,
            "events": events,
        },
    )