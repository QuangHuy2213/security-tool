import httpx

from fastapi import (
    APIRouter,
    Request,
    Response,
    HTTPException,
)

from app.core.config import settings
from app.services.security_service import security_service


router = APIRouter(
    prefix="/api",
    tags=["Cổng bảo mật"],
)


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


def build_forward_headers(request: Request):

    headers = {}

    for key, value in request.headers.items():

        if key.lower() not in HOP_BY_HOP_HEADERS:
            headers[key] = value

    return headers


@router.api_route(
    "/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def proxy_request(
    request: Request,
    path: str,
):

    # =========================
    # LẤY IP CLIENT
    # =========================

    forwarded_for = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded_for:

        client_ip = (
            forwarded_for
            .split(",")[0]
            .strip()
        )

    elif request.client:

        client_ip = request.client.host

    else:

        client_ip = "unknown"


    # =========================
    # GHI NHẬN REQUEST
    # =========================

    security_service.record_request(
        ip_address=client_ip,
        method=request.method,
        path=f"/api/{path}",
    )


    # =========================
    # URL BACKEND
    # =========================

    backend_url = (
        f"{settings.BACKEND_URL.rstrip('/')}/{path}"
    )


    body = await request.body()

    headers = build_forward_headers(
        request
    )


    try:

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        ) as client:

            backend_response = (
                await client.request(
                    method=request.method,
                    url=backend_url,
                    params=request.query_params,
                    content=body,
                    headers=headers,
                )
            )


    except httpx.TimeoutException:

        raise HTTPException(
            status_code=504,
            detail=(
                "Backend phản hồi quá "
                "thời gian cho phép."
            ),
        )


    except httpx.RequestError as exc:

        print(
            f"[ERROR] Không thể kết nối "
            f"backend: {exc}"
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Không thể kết nối "
                "tới backend."
            ),
        )


    response_headers = {}

    for key, value in (
        backend_response.headers.items()
    ):

        if (
            key.lower()
            not in HOP_BY_HOP_HEADERS
        ):
            response_headers[key] = value


    return Response(
        content=backend_response.content,
        status_code=(
            backend_response.status_code
        ),
        headers=response_headers,
        media_type=(
            backend_response.headers.get(
                "content-type"
            )
        ),
    )