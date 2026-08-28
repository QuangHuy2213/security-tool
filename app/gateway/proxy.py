import httpx

from fastapi import (
    APIRouter,
    Request,
    Response,
    HTTPException,
)

from app.core.config import settings


router = APIRouter(
    prefix="/api",
    tags=["Security Gateway"],
)


# Các header không nên forward trực tiếp
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
    """
    Chuẩn bị header để gửi sang backend NestJS.
    """

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
    """
    Nhận request từ frontend,
    sau đó chuyển tiếp tới backend NestJS.
    """

    backend_url = (
        f"{settings.BACKEND_URL.rstrip('/')}/{path}"
    )

    # Lấy body của request
    body = await request.body()

    # Lấy query parameter
    query_params = request.query_params

    # Chuẩn bị header
    headers = build_forward_headers(request)

    try:

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        ) as client:

            backend_response = await client.request(
                method=request.method,
                url=backend_url,
                params=query_params,
                content=body,
                headers=headers,
            )

    except httpx.TimeoutException:

        raise HTTPException(
            status_code=504,
            detail="Backend phản hồi quá thời gian cho phép.",
        )

    except httpx.RequestError as exc:

        print(
            f"Lỗi kết nối backend: {exc}"
        )

        raise HTTPException(
            status_code=502,
            detail="Không thể kết nối tới backend.",
        )

    # Lọc response header
    response_headers = {}

    for key, value in backend_response.headers.items():

        if key.lower() not in HOP_BY_HOP_HEADERS:
            response_headers[key] = value

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=response_headers,
        media_type=backend_response.headers.get(
            "content-type"
        ),
    )