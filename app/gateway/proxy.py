import httpx
from urllib.parse import unquote
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.services.security_service import security_service
from app.detectors.sqli_detector import detect_sqli
from app.detectors.xss_detector import detect_xss
from app.prevention.ip_blocker import ip_blocker

router = APIRouter(prefix="/api", tags=["Cổng bảo mật"])

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "host", "content-length"
}

BLOCK_THRESHOLD = 80

def build_forward_headers(request: Request):
    headers = {}
    for key, value in request.headers.items():
        if key.lower() not in HOP_BY_HOP_HEADERS:
            headers[key] = value
    return headers

def get_client_ip(request: Request):
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"

async def build_request_content(request: Request, path: str):
    parts = [unquote(path)]

    if request.url.query:
        parts.append(unquote(request.url.query))

    body = await request.body()

    if body:
        try:
            body_text = body.decode("utf-8", errors="ignore")
            parts.append(unquote(body_text))
        except Exception:
            pass

    return "\n".join(parts), body

def analyze_request(content: str):
    results = []

    sqli_result = detect_sqli(content)
    if sqli_result["detected"]:
        results.append({
            "type": "SQL Injection",
            "score": sqli_result["score"],
            "reason": "Phát hiện dữ liệu có dấu hiệu SQL Injection."
        })

    xss_result = detect_xss(content)
    if xss_result["detected"]:
        results.append({
            "type": "Cross-Site Scripting (XSS)",
            "score": xss_result["score"],
            "reason": "Phát hiện dữ liệu có dấu hiệu Cross-Site Scripting."
        })

    if not results:
        return {
            "detected": False,
            "attack_type": None,
            "risk_score": 0,
            "reason": None
        }

    highest = max(results, key=lambda item: item["score"])

    if len(results) > 1:
        risk_score = min(highest["score"] + 5, 100)
        attack_type = "Nhiều dấu hiệu tấn công"
    else:
        risk_score = highest["score"]
        attack_type = highest["type"]

    return {
        "detected": True,
        "attack_type": attack_type,
        "risk_score": risk_score,
        "reason": highest["reason"]
    }

@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
)
async def proxy_request(request: Request, path: str):
    client_ip = get_client_ip(request)
    request_path = f"/api/{path}"

    # Tất cả request đi qua Gateway đều được đếm
    security_service.record_request(
        ip_address=client_ip,
        method=request.method,
        path=request_path
    )

    # Kiểm tra IP đã bị khóa trước khi xử lý
    if ip_blocker.is_blocked(client_ip):
        blocked_info = ip_blocker.get_blocked_ip(client_ip)

        print(f"[IP ĐÃ BỊ CHẶN] {client_ip}")

        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "message": "Địa chỉ IP của bạn đã bị hệ thống bảo mật chặn.",
                "ip_address": client_ip,
                "reason": blocked_info["reason"]
            }
        )

    request_content, body = await build_request_content(request, path)
    analysis = analyze_request(request_content)

    # Phát hiện tấn công
    if analysis["detected"]:
        risk_score = analysis["risk_score"]
        action = "BLOCK" if risk_score >= BLOCK_THRESHOLD else "ALERT"

        violation = ip_blocker.register_violation(
            ip_address=client_ip,
            risk_score=risk_score,
            attack_type=analysis["attack_type"]
        )

        reason = analysis["reason"]

        if violation["blocked"]:
            reason += (
                f" IP đã bị khóa sau "
                f"{violation['violation_count']} lần vi phạm."
            )

        security_service.record_attack(
            ip_address=client_ip,
            method=request.method,
            path=request_path,
            attack_type=analysis["attack_type"],
            risk_score=risk_score,
            action=action,
            reason=reason
        )

        if action == "BLOCK":
            return JSONResponse(
                status_code=403,
                content={
                    "status": "blocked",
                    "message": "Yêu cầu đã bị hệ thống bảo mật ngăn chặn.",
                    "attack_type": analysis["attack_type"],
                    "risk_score": risk_score,
                    "violation_count": violation["violation_count"],
                    "ip_blocked": violation["blocked"]
                }
            )

    # Request an toàn mới được chuyển tới NestJS
    backend_url = f"{settings.BACKEND_URL.rstrip('/')}/{path}"
    headers = build_forward_headers(request)

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True
        ) as client:
            backend_response = await client.request(
                method=request.method,
                url=backend_url,
                params=request.query_params,
                content=body,
                headers=headers
            )

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Backend phản hồi quá thời gian cho phép."
        )

    except httpx.RequestError as exc:
        print(f"[LỖI BACKEND] {exc}")
        print(f"[BACKEND URL] {backend_url}")

        raise HTTPException(
            status_code=502,
            detail="Không thể kết nối tới backend."
        )

    response_headers = {}

    for key, value in backend_response.headers.items():
        if key.lower() not in HOP_BY_HOP_HEADERS:
            response_headers[key] = value

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=response_headers,
        media_type=backend_response.headers.get("content-type")
    )