from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates


router = APIRouter()

# Thư mục chứa giao diện HTML
templates = Jinja2Templates(
    directory="app/templates"
)


# Trang Dashboard chính
@router.get("/")
async def dashboard(request: Request):

    # Dữ liệu thống kê tạm thời
    stats = {
        "requests": 0,
        "attacks": 0,
        "blocked": 0,
        "critical": 0,
    }

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "stats": stats,
        },
    )