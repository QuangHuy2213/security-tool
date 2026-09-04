import hashlib
import json

from urllib.parse import unquote

import httpx

from fastapi import (
    APIRouter,
    Request,
    Response,
    HTTPException,
)

from fastapi.responses import JSONResponse

from app.core.config import settings

from app.services.security_service import (
    security_service,
)

from app.detectors.sqli_detector import (
    detect_sqli,
)

from app.detectors.xss_detector import (
    detect_xss,
)

from app.detectors.brute_force_detector import (
    brute_force_detector,
)

from app.prevention.ip_blocker import (
    ip_blocker,
)

from app.prevention.rate_limiter import (
    rate_limiter,
)


# =========================================================
# ROUTER
# =========================================================

router = APIRouter(
    prefix="/api",
    tags=["Cổng bảo mật"],
)


# =========================================================
# CONSTANT
# =========================================================

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

    # Không forward encoding từ browser.
    "accept-encoding",

    # Không cho client giả Gateway Secret.
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

        if (
            key.lower()
            not in HOP_BY_HOP_HEADERS
        ):
            headers[key] = value

    # Gateway Secret chỉ Security Gateway tự thêm.
    headers[
        "X-Security-Gateway-Key"
    ] = settings.GATEWAY_SECRET

    # Tránh lỗi gzip/br/zstd khi proxy response.
    headers[
        "Accept-Encoding"
    ] = "identity"

    return headers


# =========================================================
# CLIENT IP
# =========================================================

def get_client_ip(
    request: Request,
):
    forwarded_for = (
        request.headers.get(
            "x-forwarded-for"
        )
    )

    if forwarded_for:
        return (
            forwarded_for
            .split(",")[0]
            .strip()
        )

    real_ip = (
        request.headers.get(
            "x-real-ip"
        )
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
    client_id = (
        request.headers.get(
            "x-client-id"
        )
    )

    user_agent = (
        request.headers.get(
            "user-agent",
            "unknown",
        )
    )

    # Ưu tiên X-Client-Id.
    if client_id:

        raw_value = (
            f"client:"
            f"{client_id.strip()}"
        )

    # Fallback khi client không gửi X-Client-Id.
    else:

        raw_value = (
            f"{ip_address}"
            f"|"
            f"{user_agent}"
        )

    return hashlib.sha256(
        raw_value.encode(
            "utf-8"
        )
    ).hexdigest()


# =========================================================
# ĐỌC REQUEST CONTENT
# =========================================================

async def build_request_content(
    request: Request,
    path: str,
):
    parts = [
        unquote(path)
    ]

    # Query string.
    if request.url.query:

        parts.append(
            unquote(
                request.url.query
            )
        )

    # Body.
    body = await request.body()

    if body:

        try:

            body_text = (
                body.decode(
                    "utf-8",
                    errors="ignore",
                )
            )

            parts.append(
                unquote(
                    body_text
                )
            )

        except Exception:
            pass

    return (
        "\n".join(parts),
        body,
    )


# =========================================================
# EXTRACT LOGIN IDENTIFIER
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
            or
            payload.get("username")
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
# BACKEND MESSAGE
# =========================================================

def get_backend_message(
    backend_response: httpx.Response,
):
    try:

        payload = (
            backend_response.json()
        )

        message = payload.get(
            "message"
        )

        if isinstance(
            message,
            list,
        ):

            return " ".join(
                str(item)
                for item
                in message
            )

        if message is None:
            return ""

        return str(message)

    except Exception:
        return ""


# =========================================================
# SQL INJECTION + XSS ANALYSIS
# =========================================================

def analyze_request(
    content: str,
):
    results = []

    # -----------------------------------------------------
    # SQL Injection
    # -----------------------------------------------------

    sqli_result = (
        detect_sqli(
            content
        )
    )

    if sqli_result[
        "detected"
    ]:

        results.append({
            "type":
                "SQL Injection",

            "score":
                sqli_result[
                    "score"
                ],

            "reason": (
                "Phát hiện dữ liệu "
                "có dấu hiệu SQL Injection."
            ),
        })

    # -----------------------------------------------------
    # XSS
    # -----------------------------------------------------

    xss_result = (
        detect_xss(
            content
        )
    )

    if xss_result[
        "detected"
    ]:

        results.append({
            "type": (
                "Cross-Site "
                "Scripting (XSS)"
            ),

            "score":
                xss_result[
                    "score"
                ],

            "reason": (
                "Phát hiện dữ liệu "
                "có dấu hiệu "
                "Cross-Site Scripting."
            ),
        })

    # -----------------------------------------------------
    # Không phát hiện
    # -----------------------------------------------------

    if not results:

        return {
            "detected": False,
            "attack_type": None,
            "risk_score": 0,
            "reason": None,
        }

    # Lấy threat có risk cao nhất.
    highest = max(
        results,
        key=lambda item:
            item["score"],
    )

    # -----------------------------------------------------
    # Có nhiều loại attack cùng lúc
    # -----------------------------------------------------

    if len(results) > 1:

        return {
            "detected": True,

            "attack_type": (
                "Nhiều dấu hiệu "
                "tấn công"
            ),

            "risk_score": min(
                highest["score"]
                + 5,
                100,
            ),

            "reason":
                highest["reason"],
        }

    return {
        "detected": True,

        "attack_type":
            highest["type"],

        "risk_score":
            highest["score"],

        "reason":
            highest["reason"],
    }


# =========================================================
# RATE LIMIT RESPONSE
# =========================================================

async def build_rate_limited_response(
    *,
    rate_result,
    client_ip,
    client_key,
    user_agent,
    method,
    request_path,
):
    """
    Một burst vượt Rate Limit chỉ tạo đúng một
    API Abuse strike.

    Các request 429 tiếp theo trong cùng window:
    - không tăng strike
    - không tăng ClientViolation
    - không tạo SecurityEvent mới
    """

    risk_score = (
        settings
        .RATE_LIMIT_RISK_SCORE
    )

    strikes = None

    globally_blocked = False

    reason = (
        "Client vượt Rate Limit. "
        f"Request: "
        f"{rate_result['count']}/"
        f"{rate_result['limit']}. "
        f"Window: "
        f"{settings.RATE_LIMIT_WINDOW_SECONDS}s. "
        f"Group: "
        f"{rate_result['group']}."
    )

    # =====================================================
    # CHỈ REQUEST ĐẦU TIÊN VƯỢT LIMIT
    # TRONG WINDOW MỚI TẠO STRIKE
    # =====================================================

    if rate_result[
        "new_burst"
    ]:

        abuse = (
            await rate_limiter
            .register_abuse_strike(
                client_key
            )
        )

        strikes = (
            abuse["strikes"]
        )

        escalated = (
            abuse["escalated"]
        )

        # -------------------------------------------------
        # Ghi 1 event / burst.
        #
        # Strike bình thường:
        # ALERT
        #
        # Strike đạt escalation:
        # BLOCK
        # -------------------------------------------------

        await security_service.record_attack(
            ip_address=client_ip,
            client_key=client_key,
            user_agent=user_agent,
            method=method,
            path=request_path,
            attack_type="API Abuse",
            risk_score=risk_score,
            action=(
                "BLOCK"
                if escalated
                else "ALERT"
            ),
            reason=(
                f"{reason} "
                f"Strike "
                f"{strikes}/"
                f"{abuse['max_strikes']}."
            ),
        )

        # =================================================
        # PERSISTENT API ABUSE
        #
        # Chỉ khi đủ số strike mới global block.
        # =================================================

        if escalated:

            violation = (
                await ip_blocker
                .register_violation(
                    ip_address=client_ip,
                    client_key=client_key,
                    risk_score=risk_score,
                    attack_type="API Abuse",
                )
            )

            # API Abuse escalation phải global block
            # bất kể risk 60 chưa đạt IMMEDIATE_BLOCK_SCORE.
            await ip_blocker.block_ip(
                ip_address=client_ip,
                client_key=client_key,

                reason=(
                    "Persistent API Abuse. "
                    f"Phát hiện "
                    f"{strikes} đợt vượt "
                    f"Rate Limit trong "
                    f"{settings.API_ABUSE_STRIKE_WINDOW_SECONDS} "
                    f"giây."
                ),

                violation_count=(
                    violation[
                        "violation_count"
                    ]
                ),

                total_risk=(
                    violation[
                        "total_risk"
                    ]
                ),
            )

            globally_blocked = True

    retry_after = (
        rate_result[
            "retry_after"
        ]
    )

    # Request hiện tại vẫn là request bị rate-limit.
    # Nếu nó vừa kích hoạt global block,
    # request kế tiếp sẽ nhận 403 client_blocked.
    return JSONResponse(
        status_code=429,

        content={
            "status":
                "rate_limited",

            "message": (
                "Bạn gửi quá nhiều yêu cầu. "
                "Vui lòng thử lại sau."
            ),

            "retry_after":
                retry_after,

            "request_count":
                rate_result[
                    "count"
                ],

            "limit":
                rate_result[
                    "limit"
                ],

            "rate_limit_group":
                rate_result[
                    "group"
                ],

            "api_abuse_strikes":
                strikes,

            "client_blocked":
                globally_blocked,
        },

        headers={
            "Retry-After": str(
                retry_after
            )
        },
    )


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
    # 1. CLIENT INFORMATION
    # =====================================================

    client_ip = (
        get_client_ip(
            request
        )
    )

    client_key = (
        get_client_key(
            request,
            client_ip,
        )
    )

    user_agent = (
        request.headers.get(
            "user-agent",
            "unknown",
        )
    )

    request_path = (
        f"/api/{path}"
    )

    normalized_path = (
        path.strip("/")
    )

    is_login_request = (
        request.method.upper()
        == "POST"

        and

        normalized_path
        == LOGIN_PATH
    )

    print(
        f"[CLIENT] "
        f"IP={client_ip} "
        f"| Key="
        f"{client_key[:12]} "
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
                "status":
                    "client_blocked",

                "message": (
                    "Client đang bị hệ thống "
                    "bảo mật chặn."
                ),

                "reason":
                    blocked_info[
                        "reason"
                    ],

                "retry_after":
                    blocked_info.get(
                        "remaining_seconds"
                    ),
            },
        )


    # =====================================================
    # 4. READ REQUEST
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
    # 5. BRUTE FORCE PRE-CHECK
    #
    # Login dùng cơ chế riêng.
    # Không áp dụng generic Rate Limit cho login.
    # =====================================================

    if (
        is_login_request
        and
        login_identifier
    ):

        login_block = (
            await brute_force_detector
            .check_blocked(
                client_key=client_key,
                identifier=(
                    login_identifier
                ),
                endpoint=request_path,
            )
        )

        if login_block[
            "blocked"
        ]:

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
                    "status":
                        "login_blocked",

                    "message": (
                        "Đăng nhập tạm thời "
                        "bị khóa do có quá nhiều "
                        "lần đăng nhập không "
                        "thành công."
                    ),

                    "retry_after":
                        retry_after,
                },

                headers={
                    "Retry-After": str(
                        retry_after
                    )
                },
            )


    # =====================================================
    # 6. RATE LIMIT / API ABUSE
    #
    # Login KHÔNG đi qua generic Rate Limit.
    #
    # OPTIONS / HEAD không tính Rate Limit.
    # =====================================================

    if (
        not is_login_request

        and

        request.method.upper()
        not in {
            "OPTIONS",
            "HEAD",
        }
    ):

        rate_result = (
            await rate_limiter.check(
                client_key=client_key,
                endpoint=request_path,
                method=request.method,
            )
        )

        if not rate_result[
            "allowed"
        ]:

            return (
                await
                build_rate_limited_response(
                    rate_result=rate_result,
                    client_ip=client_ip,
                    client_key=client_key,
                    user_agent=user_agent,
                    method=request.method,
                    request_path=(
                        request_path
                    ),
                )
            )


    # =====================================================
    # 7. SQL INJECTION / XSS
    # =====================================================

    analysis = (
        analyze_request(
            request_content
        )
    )

    if analysis[
        "detected"
    ]:

        risk_score = (
            analysis[
                "risk_score"
            ]
        )

        action = (
            "BLOCK"

            if (
                risk_score
                >= BLOCK_THRESHOLD
            )

            else "ALERT"
        )

        violation = (
            await ip_blocker
            .register_violation(
                ip_address=client_ip,
                client_key=client_key,
                risk_score=risk_score,
                attack_type=(
                    analysis[
                        "attack_type"
                    ]
                ),
            )
        )

        reason = (
            analysis[
                "reason"
            ]
        )

        if violation[
            "blocked"
        ]:

            reason += (
                " Client đã bị khóa sau "
                f"{violation['violation_count']} "
                "lần vi phạm."
            )

        await security_service.record_attack(
            ip_address=client_ip,
            client_key=client_key,
            user_agent=user_agent,
            method=request.method,
            path=request_path,
            attack_type=(
                analysis[
                    "attack_type"
                ]
            ),
            risk_score=risk_score,
            action=action,
            reason=reason,
        )

        if action == "BLOCK":

            return JSONResponse(
                status_code=403,

                content={
                    "status":
                        "blocked",

                    "message": (
                        "Yêu cầu đã bị hệ thống "
                        "bảo mật ngăn chặn."
                    ),

                    "attack_type":
                        analysis[
                            "attack_type"
                        ],

                    "risk_score":
                        risk_score,

                    "violation_count":
                        violation[
                            "violation_count"
                        ],

                    "ip_blocked":
                        violation[
                            "blocked"
                        ],
                },
            )


    # =====================================================
    # 8. CHECK GATEWAY SECRET
    # =====================================================

    if not settings.GATEWAY_SECRET:

        print(
            "[GATEWAY ERROR] "
            "GATEWAY_SECRET chưa được cấu hình."
        )

        raise HTTPException(
            status_code=500,

            detail=(
                "Security Gateway "
                "chưa được cấu hình đầy đủ."
            ),
        )


    # =====================================================
    # 9. FORWARD TO NESTJS
    # =====================================================

    backend_url = (
        f"{settings.BACKEND_URL.rstrip('/')}"
        f"/{path}"
    )

    # Chỉ log trạng thái.
    # Không log secret thực tế.
    print(
        "[GATEWAY] "
        "Secret configured:",
        bool(
            settings.GATEWAY_SECRET
        ),
    )

    headers = (
        build_forward_headers(
            request
        )
    )

    try:

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                60.0
            ),
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
                "Backend phản hồi "
                "quá thời gian cho phép."
            ),
        )

    except httpx.RequestError as exc:

        print(
            f"[LỖI BACKEND] "
            f"{exc}"
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
    # 10. LOGIN RESPONSE ANALYSIS
    # =====================================================

    if (
        is_login_request
        and
        login_identifier
    ):

        # -------------------------------------------------
        # LOGIN SUCCESS
        # -------------------------------------------------

        if (
            200
            <= backend_response.status_code
            < 300
        ):

            await (
                brute_force_detector
                .reset_success(
                    client_key=client_key,
                    identifier=(
                        login_identifier
                    ),
                    endpoint=request_path,
                )
            )

            print(
                f"[LOGIN SUCCESS] "
                f"Client="
                f"{client_key[:12]}"
            )


        # -------------------------------------------------
        # LOGIN FAILURE
        # -------------------------------------------------

        elif (
            backend_response.status_code
            == 401
        ):

            backend_message = (
                get_backend_message(
                    backend_response
                )
            )

            # Chỉ tính lỗi email/password.
            #
            # Không tính các lỗi authentication
            # không liên quan như Google account.
            if (
                backend_message
                == INVALID_LOGIN_MESSAGE
            ):

                failure = (
                    await
                    brute_force_detector
                    .register_failure(
                        client_key=client_key,
                        identifier=(
                            login_identifier
                        ),
                        endpoint=(
                            request_path
                        ),
                    )
                )

                print(
                    f"[LOGIN FAIL] "
                    f"Client="
                    f"{client_key[:12]} "
                    f"| Count="
                    f"{failure['failed_count']}"
                )


                # =========================================
                # VỪA ĐẠT NGƯỠNG BRUTE FORCE
                #
                # Chỉ request này mới ghi event.
                # =========================================

                if failure.get(
                    "newly_blocked",
                    False,
                ):

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

                    await (
                        security_service
                        .record_attack(
                            ip_address=(
                                client_ip
                            ),
                            client_key=(
                                client_key
                            ),
                            user_agent=(
                                user_agent
                            ),
                            method=(
                                request.method
                            ),
                            path=(
                                request_path
                            ),
                            attack_type=(
                                "Brute Force"
                            ),
                            risk_score=(
                                risk_score
                            ),
                            action="BLOCK",
                            reason=reason,
                        )
                    )


                # =========================================
                # LOGIN HIỆN ĐANG BỊ KHÓA
                #
                # - newly_blocked=True:
                #   request vừa kích hoạt block.
                #
                # - newly_blocked=False:
                #   request concurrent hoặc request sau.
                #
                # Cả hai đều phải trả 429.
                # =========================================

                if failure.get(
                    "blocked",
                    False,
                ):

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
                            "status":
                                "login_blocked",

                            "message": (
                                "Phát hiện quá nhiều "
                                "lần đăng nhập thất bại. "
                                "Đăng nhập đã bị khóa "
                                "tạm thời."
                            ),

                            "attack_type":
                                "Brute Force",

                            "risk_score": (
                                settings
                                .BRUTE_FORCE_RISK_SCORE
                            ),

                            "failed_count":
                                failure[
                                    "failed_count"
                                ],

                            "retry_after":
                                retry_after,
                        },

                        headers={
                            "Retry-After": str(
                                retry_after
                            )
                        },
                    )


    # =====================================================
    # 11. RESPONSE HEADERS
    # =====================================================

    response_headers = {}

    for (
        key,
        value,
    ) in (
        backend_response
        .headers
        .items()
    ):

        if (
            key.lower()
            not in HOP_BY_HOP_HEADERS
        ):
            response_headers[
                key
            ] = value


    # =====================================================
    # 12. CONTENT TYPE
    # =====================================================

    content_type = (
        backend_response
        .headers
        .get(
            "content-type"
        )
    )


    # =====================================================
    # 13. RETURN RESPONSE
    # =====================================================

    return Response(
        content=(
            backend_response.content
        ),

        status_code=(
            backend_response
            .status_code
        ),

        headers=(
            response_headers
        ),

        media_type=(
            content_type
        ),
    )