import hashlib
import json
import httpx

from urllib.parse import unquote

from fastapi import (
    APIRouter,
    Request,
    Response,
    HTTPException,
)

from fastapi.responses import JSONResponse

from app.core.config import settings
from app.services.security_service import security_service
from app.detectors.sqli_detector import detect_sqli
from app.detectors.xss_detector import detect_xss
from app.detectors.brute_force_detector import brute_force_detector
from app.prevention.ip_blocker import ip_blocker
from app.prevention.rate_limiter import rate_limiter


router = APIRouter(
    prefix="/api",
    tags=["Cổng bảo mật"],
)

BLOCK_THRESHOLD = 80

LOGIN_PATH = "auth/login"

INVALID_LOGIN_MESSAGE = (
    "Tài khoản không đúng hoặc không tồn tại!"
)

SECURITY_GATEWAY_HEADER = (
    "x-security-gateway-key"
)


# =========================================================
# HEADERS KHÔNG ĐƯỢC FORWARD TRỰC TIẾP
# =========================================================

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
    "content-encoding",

    # Không forward Accept-Encoding từ browser
    # để tránh backend trả gzip/br/zstd gây lỗi proxy
    "accept-encoding",

    # Không cho client tự giả Gateway Secret
    SECURITY_GATEWAY_HEADER,
}


# =========================================================
# BUILD FORWARD HEADERS
# =========================================================

def build_forward_headers(
    request: Request,
):
    headers = {}

    for key, value in request.headers.items():
        if key.lower() not in HOP_BY_HOP_HEADERS:
            headers[key] = value

    # Gateway Secret chỉ Security Tool tự thêm
    headers["X-Security-Gateway-Key"] = (
        settings.GATEWAY_SECRET
    )

    # Yêu cầu NestJS trả response không nén
    headers["Accept-Encoding"] = "identity"

    return headers


# =========================================================
# CLIENT IP
# =========================================================

def get_client_ip(
    request: Request,
):
    forwarded_for = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded_for:
        return (
            forwarded_for
            .split(",")[0]
            .strip()
        )

    real_ip = request.headers.get(
        "x-real-ip"
    )

    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return "unknown"


# =========================================================
# CLIENT KEY
# =========================================================

def get_client_key(
    request: Request,
    ip_address: str,
):
    client_id = request.headers.get(
        "x-client-id"
    )

    user_agent = request.headers.get(
        "user-agent",
        "unknown",
    )

    if client_id:
        raw_value = (
            f"client:{client_id.strip()}"
        )
    else:
        raw_value = (
            f"{ip_address}|{user_agent}"
        )

    return hashlib.sha256(
        raw_value.encode("utf-8")
    ).hexdigest()


# =========================================================
# ĐỌC REQUEST
# =========================================================

async def build_request_content(
    request: Request,
    path: str,
):
    parts = [
        unquote(path)
    ]

    if request.url.query:
        parts.append(
            unquote(
                request.url.query
            )
        )

    body = await request.body()

    if body:
        try:
            body_text = body.decode(
                "utf-8",
                errors="ignore",
            )

            parts.append(
                unquote(body_text)
            )

        except Exception:
            pass

    return "\n".join(parts), body


# =========================================================
# LẤY EMAIL / USERNAME LOGIN
# =========================================================

def extract_login_identifier(
    body: bytes,
):
    if not body:
        return None

    try:
        payload = json.loads(
            body.decode(
                "utf-8",
                errors="ignore",
            )
        )

        identifier = (
            payload.get("email")
            or payload.get("username")
        )

        if not identifier:
            return None

        return (
            str(identifier)
            .strip()
            .lower()
        )

    except Exception:
        return None


# =========================================================
# LẤY MESSAGE TỪ BACKEND
# =========================================================

def get_backend_message(
    backend_response: httpx.Response,
):
    try:
        payload = backend_response.json()

        message = payload.get(
            "message"
        )

        if isinstance(message, list):
            return " ".join(
                str(item)
                for item in message
            )

        if message is None:
            return ""

        return str(message)

    except Exception:
        return ""


# =========================================================
# SQL INJECTION + XSS
# =========================================================

def analyze_request(
    content: str,
):
    results = []

    # SQL Injection
    sqli_result = detect_sqli(
        content
    )

    if sqli_result["detected"]:
        results.append({
            "type": "SQL Injection",
            "score": sqli_result["score"],
            "reason": (
                "Phát hiện dữ liệu có dấu hiệu "
                "SQL Injection."
            ),
        })

    # XSS
    xss_result = detect_xss(
        content
    )

    if xss_result["detected"]:
        results.append({
            "type": (
                "Cross-Site Scripting (XSS)"
            ),
            "score": xss_result["score"],
            "reason": (
                "Phát hiện dữ liệu có dấu hiệu "
                "Cross-Site Scripting."
            ),
        })

    # Không phát hiện
    if not results:
        return {
            "detected": False,
            "attack_type": None,
            "risk_score": 0,
            "reason": None,
        }

    highest = max(
        results,
        key=lambda item: item["score"],
    )

    # Nhiều dấu hiệu cùng lúc
    if len(results) > 1:
        return {
            "detected": True,
            "attack_type": (
                "Nhiều dấu hiệu tấn công"
            ),
            "risk_score": min(
                highest["score"] + 5,
                100,
            ),
            "reason": highest["reason"],
        }

    return {
        "detected": True,
        "attack_type": highest["type"],
        "risk_score": highest["score"],
        "reason": highest["reason"],
    }


# =========================================================
# SECURITY GATEWAY
# =========================================================

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
    # =====================================================
    # 1. CLIENT
    # =====================================================

    client_ip = get_client_ip(
        request
    )

    client_key = get_client_key(
        request,
        client_ip,
    )

    user_agent = request.headers.get(
        "user-agent",
        "unknown",
    )

    request_path = (
        f"/api/{path}"
    )

    normalized_path = (
        path.strip("/")
    )

    is_login_request = (
        request.method == "POST"
        and normalized_path == LOGIN_PATH
    )

    print(
        f"[CLIENT] "
        f"IP={client_ip} "
        f"| Key={client_key[:12]} "
        f"| {request.method} "
        f"{request_path}"
    )


    # =====================================================
    # 2. TOTAL REQUEST
    # =====================================================

    await security_service.record_request(
        ip_address=client_ip,
        method=request.method,
        path=request_path,
    )


    # =====================================================
    # 3. GLOBAL BLOCK
    # =====================================================

    blocked_info = (
        await ip_blocker.is_blocked(
            ip_address=client_ip,
            client_key=client_key,
        )
    )

    if blocked_info:
        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "message": (
                    "Client đang bị hệ thống "
                    "bảo mật chặn."
                ),
                "reason": (
                    blocked_info["reason"]
                ),
            },
        )


    # =====================================================
    # 4. ĐỌC BODY
    # =====================================================

    request_content, body = (
        await build_request_content(
            request,
            path,
        )
    )

    login_identifier = None

    if is_login_request:
        login_identifier = (
            extract_login_identifier(
                body
            )
        )


    # =====================================================
    # 5. BRUTE FORCE CHECK
    # =====================================================

    if (
        is_login_request
        and login_identifier
    ):
        login_block = (
            await brute_force_detector
            .check_blocked(
                client_key=client_key,
                identifier=login_identifier,
                endpoint=request_path,
            )
        )

        if login_block["blocked"]:
            retry_after = (
                login_block.get(
                    "retry_after",
                    settings
                    .BRUTE_FORCE_BLOCK_SECONDS,
                )
            )

            return JSONResponse(
                status_code=429,
                content={
                    "status": "login_blocked",
                    "message": (
                        "Đăng nhập tạm thời bị khóa "
                        "do có quá nhiều lần đăng nhập "
                        "không thành công."
                    ),
                    "retry_after": (
                        retry_after
                    ),
                },
                headers={
                    "Retry-After": str(
                        retry_after
                    )
                },
            )


    # =====================================================
    # 6. RATE LIMIT / API ABUSE
    # Login dùng Brute Force riêng
    # =====================================================

    if (
        not is_login_request
        and request.method not in {
            "OPTIONS",
            "HEAD",
        }
    ):
        rate_result = (
            await rate_limiter.check(
                client_key=client_key,
                endpoint=request_path,
            )
        )

        if not rate_result["allowed"]:
            risk_score = (
                settings
                .RATE_LIMIT_RISK_SCORE
            )

            violation = (
                await ip_blocker
                .register_violation(
                    ip_address=client_ip,
                    client_key=client_key,
                    risk_score=risk_score,
                    attack_type="API Abuse",
                )
            )

            reason = (
                f"Client gửi quá nhiều request: "
                f"{rate_result['count']}/"
                f"{rate_result['limit']} request "
                f"trong "
                f"{settings.RATE_LIMIT_WINDOW_SECONDS} "
                f"giây."
            )

            if violation["blocked"]:
                reason += (
                    f" Client đã bị khóa sau "
                    f"{violation['violation_count']} "
                    f"lần vi phạm."
                )

            await security_service.record_attack(
                ip_address=client_ip,
                client_key=client_key,
                user_agent=user_agent,
                method=request.method,
                path=request_path,
                attack_type="API Abuse",
                risk_score=risk_score,
                action="BLOCK",
                reason=reason,
            )

            retry_after = (
                rate_result.get(
                    "retry_after",
                    settings
                    .RATE_LIMIT_WINDOW_SECONDS,
                )
            )

            return JSONResponse(
                status_code=429,
                content={
                    "status": "rate_limited",
                    "message": (
                        "Bạn gửi quá nhiều yêu cầu. "
                        "Vui lòng thử lại sau."
                    ),
                    "attack_type": "API Abuse",
                    "risk_score": risk_score,
                    "request_count": (
                        rate_result["count"]
                    ),
                    "limit": (
                        rate_result["limit"]
                    ),
                    "retry_after": retry_after,
                    "violation_count": (
                        violation[
                            "violation_count"
                        ]
                    ),
                    "ip_blocked": (
                        violation["blocked"]
                    ),
                },
                headers={
                    "Retry-After": str(
                        retry_after
                    )
                },
            )


    # =====================================================
    # 7. SQL INJECTION / XSS
    # =====================================================

    analysis = analyze_request(
        request_content
    )

    if analysis["detected"]:
        risk_score = (
            analysis["risk_score"]
        )

        action = (
            "BLOCK"
            if risk_score >= BLOCK_THRESHOLD
            else "ALERT"
        )

        violation = (
            await ip_blocker
            .register_violation(
                ip_address=client_ip,
                client_key=client_key,
                risk_score=risk_score,
                attack_type=(
                    analysis["attack_type"]
                ),
            )
        )

        reason = (
            analysis["reason"]
        )

        if violation["blocked"]:
            reason += (
                f" Client đã bị khóa sau "
                f"{violation['violation_count']} "
                f"lần vi phạm."
            )

        await security_service.record_attack(
            ip_address=client_ip,
            client_key=client_key,
            user_agent=user_agent,
            method=request.method,
            path=request_path,
            attack_type=(
                analysis["attack_type"]
            ),
            risk_score=risk_score,
            action=action,
            reason=reason,
        )

        if action == "BLOCK":
            return JSONResponse(
                status_code=403,
                content={
                    "status": "blocked",
                    "message": (
                        "Yêu cầu đã bị hệ thống "
                        "bảo mật ngăn chặn."
                    ),
                    "attack_type": (
                        analysis[
                            "attack_type"
                        ]
                    ),
                    "risk_score": risk_score,
                    "violation_count": (
                        violation[
                            "violation_count"
                        ]
                    ),
                    "ip_blocked": (
                        violation["blocked"]
                    ),
                },
            )


    # =====================================================
    # 8. KIỂM TRA GATEWAY SECRET
    # =====================================================

    if not settings.GATEWAY_SECRET:
        print(
            "[GATEWAY ERROR] "
            "GATEWAY_SECRET chưa được cấu hình."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Security Gateway chưa được "
                "cấu hình đầy đủ."
            ),
        )


    # =====================================================
    # 9. FORWARD SANG NESTJS
    # =====================================================

    backend_url = (
        f"{settings.BACKEND_URL.rstrip('/')}"
        f"/{path}"
    )

    # Debug nhưng không in secret thật
    print(
        "[GATEWAY] Secret configured:",
        bool(settings.GATEWAY_SECRET)
    )

    print(
        "[GATEWAY] Secret length:",
        len(
            settings.GATEWAY_SECRET
            or ""
        )
    )

    headers = build_forward_headers(
        request
    )

    print(
        "[GATEWAY] Header attached:",
        "X-Security-Gateway-Key"
        in headers
    )

    print(
        "[GATEWAY] Accept-Encoding:",
        headers.get(
            "Accept-Encoding"
        )
    )

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0),
            follow_redirects=True,
        ) as http_client:

            backend_response = (
                await http_client.request(
                    method=request.method,
                    url=backend_url,
                    params=(
                        request.query_params
                    ),
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
            f"[LỖI BACKEND] {exc}"
        )

        print(
            f"[BACKEND URL] "
            f"{backend_url}"
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Không thể kết nối "
                "tới backend."
            ),
        )


    # =====================================================
    # 10. PHÂN TÍCH LOGIN RESPONSE
    # =====================================================

    if (
        is_login_request
        and login_identifier
    ):
        # LOGIN THÀNH CÔNG
        if (
            200
            <= backend_response.status_code
            < 300
        ):
            await brute_force_detector.reset_success(
                client_key=client_key,
                identifier=login_identifier,
                endpoint=request_path,
            )

            print(
                f"[LOGIN SUCCESS] "
                f"Client={client_key[:12]}"
            )

        # LOGIN THẤT BẠI
        elif (
            backend_response.status_code
            == 401
        ):
            backend_message = (
                get_backend_message(
                    backend_response
                )
            )

            # Chỉ tính sai email/password
            # Không tính tài khoản Google
            if (
                backend_message
                == INVALID_LOGIN_MESSAGE
            ):
                failure = (
                    await brute_force_detector
                    .register_failure(
                        client_key=client_key,
                        identifier=(
                            login_identifier
                        ),
                        endpoint=request_path,
                    )
                )

                print(
                    f"[LOGIN FAIL] "
                    f"Client={client_key[:12]} "
                    f"| Count="
                    f"{failure['failed_count']}"
                )

                if failure["blocked"]:
                    risk_score = (
                        settings
                        .BRUTE_FORCE_RISK_SCORE
                    )

                    reason = (
                        "Phát hiện nhiều lần "
                        "đăng nhập thất bại. "
                        f"Số lần: "
                        f"{failure['failed_count']}. "
                        "Đăng nhập đã bị khóa "
                        "tạm thời."
                    )

                    await security_service.record_attack(
                        ip_address=client_ip,
                        client_key=client_key,
                        user_agent=user_agent,
                        method=request.method,
                        path=request_path,
                        attack_type="Brute Force",
                        risk_score=risk_score,
                        action="BLOCK",
                        reason=reason,
                    )

                    retry_after = (
                        failure.get(
                            "retry_after",
                            settings
                            .BRUTE_FORCE_BLOCK_SECONDS,
                        )
                    )

                    return JSONResponse(
                        status_code=429,
                        content={
                            "status": (
                                "login_blocked"
                            ),
                            "message": (
                                "Phát hiện quá nhiều "
                                "lần đăng nhập thất bại. "
                                "Đăng nhập đã bị khóa "
                                "tạm thời."
                            ),
                            "attack_type": (
                                "Brute Force"
                            ),
                            "risk_score": (
                                risk_score
                            ),
                            "failed_count": (
                                failure[
                                    "failed_count"
                                ]
                            ),
                            "retry_after": (
                                retry_after
                            ),
                        },
                        headers={
                            "Retry-After": str(
                                retry_after
                            )
                        },
                    )


    # =====================================================
    # 11. RESPONSE TỪ NESTJS
    # =====================================================

    response_headers = {}

    for key, value in (
        backend_response.headers.items()
    ):
        # Không forward các header encoding/length cũ
        # vì body đã được httpx xử lý
        if (
            key.lower()
            not in HOP_BY_HOP_HEADERS
        ):
            response_headers[key] = value


    # Lấy content-type
    content_type = (
        backend_response.headers.get(
            "content-type"
        )
    )


    # =====================================================
    # 12. TRẢ RESPONSE VỀ FRONTEND
    # =====================================================

    return Response(
        content=backend_response.content,
        status_code=(
            backend_response.status_code
        ),
        headers=response_headers,
        media_type=content_type,
    )