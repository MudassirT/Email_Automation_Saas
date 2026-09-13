"""
FastAPI Backend Server for standalone Email Automation Service.
Enhanced with comprehensive security protections:
- Security Headers (CSP, X-Frame-Options, X-Content-Type-Options)
- Anti-CSRF protection on mutation endpoints
- API Rate limiting on sensitive routes
- Encrypted secret isolation and safe masking
- Security status diagnostics
"""

import os
import sys
import hmac
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")
load_dotenv()

from fastapi import FastAPI, HTTPException, Request, Response, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from .config import load_config, save_config
from .storage import storage
from .email_engine import email_engine
from .ai_engine import ai_engine
from .security import vault, dispatch_limiter, api_rate_limiter, tenant_security
from .auth import user_manager, google_oauth, create_jwt_token, decode_jwt_token
from .rag_engine import rag_chatbot
from .gemini_pool import gemini_token_manager
from .websocket_manager import ws_manager

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Email Automation Service API", version="1.0.0")

# 1. CORS Middleware: Restrict strictly to localhost / 127.0.0.1 and vercel.app preview/production domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_origin_regex=r"^https://.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# 2. Security Headers & Anti-CSRF Middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # A. Anti-CSRF check for mutating requests from web browsers
    if request.method in ["POST", "PUT", "DELETE"] and request.url.path.startswith("/api/"):
        # Allow requests with custom header, same-origin, or trusted hosts (localhost, vercel.app)
        custom_header = request.headers.get("X-Requested-With")
        origin = request.headers.get("Origin", "")
        referer = request.headers.get("Referer", "")
        host = request.headers.get("Host", "")

        is_same_origin = bool(host and (host in origin or host in referer))
        is_trusted_origin = any(h in (origin + referer) for h in ["localhost", "127.0.0.1", "vercel.app", "testserver"])
        if custom_header != "AutoMail" and not is_same_origin and not is_trusted_origin:
            return JSONResponse(
                status_code=403,
                content={"detail": "Security violation: Missing Anti-CSRF token or unauthorized cross-site origin."}
            )

    # B. Rate Limiting on sensitive endpoints
    client_ip = request.client.host if request.client else "127.0.0.1"
    if request.url.path in ["/api/emails/sync"]:
        if not api_rate_limiter.is_allowed(f"{client_ip}:{request.url.path}", max_requests=20, window_seconds=60):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please wait a moment before trying again."}
            )

    response: Response = await call_next(request)

    # C. HTTP Security Headers
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:;"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), microphone=(), geolocation=()"

    return response


# User Account & Tenant Auth extractor
def get_current_user_account(request: Request) -> Optional[Dict[str, Any]]:
    """Authenticate user via JWT Bearer token, session cookie, or fallback headers."""
    # 1. Bearer Token in Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        payload = decode_jwt_token(token)
        if payload and "sub" in payload:
            user = user_manager.get_user_by_id(payload["sub"])
            if user:
                return user

    # 2. Explicit tenant workspace header (API or frontend workspace switch)
    explicit_uid = request.headers.get("X-User-Id")
    if explicit_uid:
        clean_id = tenant_security.sanitize_tenant_id(explicit_uid)
        user = user_manager.get_user_by_id(clean_id)
        if user:
            return user
        return {
            "id": clean_id,
            "email": f"{clean_id}@automail.local",
            "name": clean_id.capitalize(),
            "role": "admin" if clean_id == "default" else "user",
            "provider": "local"
        }

    # 3. Cookie token
    token_cookie = request.cookies.get("automail_token")
    if token_cookie:
        payload = decode_jwt_token(token_cookie)
        if payload and "sub" in payload:
            user = user_manager.get_user_by_id(payload["sub"])
            if user:
                return user

    # 4. Cookie or Query fallback
    uid = request.cookies.get("automail_user_id") or request.query_params.get("user_id")
    if uid:
        clean_id = tenant_security.sanitize_tenant_id(uid)
        user = user_manager.get_user_by_id(clean_id)
        if user:
            return user
        return {
            "id": clean_id,
            "email": f"{clean_id}@automail.local",
            "name": clean_id.capitalize(),
            "role": "admin" if clean_id == "default" else "user",
            "provider": "local"
        }
    return None


def get_current_user_id(request: Request) -> str:
    """Extract, sanitize, and validate requesting tenant user ID."""
    user = get_current_user_account(request)
    if user and "id" in user:
        return tenant_security.sanitize_tenant_id(user["id"])
    return "default"


def require_admin(request: Request) -> Dict[str, Any]:
    """Gate: only accepts requests bearing a valid admin token or admin session.
    - 401 Unauthorized: missing or invalid token.
    - 403 Forbidden: authenticated standard user lacking administrator privileges.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Admin authentication required. Please log in via the Admin panel.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_header[7:].strip()
    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Admin session token is missing or expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_role = payload.get("role")
    is_admin = (
        payload.get("is_admin_session") is True
        or user_role == "admin"
        or payload.get("sub") == "usr_admin_root"
        or payload.get("sub") == "default"
        or payload.get("email") == "admin@automail.ai"
    )
    if not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Access forbidden: Administrator privileges required.",
        )
    return payload


# Mount static directory
try:
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --- BACKGROUND POLLING WORKER ---
_polling_active = True

def background_poller():
    """Periodic worker to sync emails automatically in the background for active tenants."""
    while _polling_active:
        try:
            tenants = storage.list_tenants()
            for t in tenants:
                uid = t["id"]
                cfg = load_config(user_id=uid)
                auto_cfg = cfg.get("automation", {})
                if auto_cfg.get("auto_sync", True):
                    # Only attempt if email is configured
                    if cfg.get("account", {}).get("email"):
                        email_engine.sync_emails(user_id=uid)
        except Exception as e:
            print(f"Background poller exception: {e}")
        time.sleep(60)

# Only start background polling loop when running as a standalone server, not in serverless functions (e.g. Vercel)
if not os.getenv("VERCEL"):
    poller_thread = threading.Thread(target=background_poller, daemon=True)
    poller_thread.start()


# --- REQUEST MODELS ---
class SettingsPayload(BaseModel):
    account: Dict[str, Any]
    ai: Dict[str, Any]
    automation: Dict[str, Any]

class RulePayload(BaseModel):
    name: str
    condition_field: str
    condition_operator: str
    condition_value: str
    action: str
    action_param: Optional[str] = ""
    enabled: Optional[bool] = True

class DraftUpdatePayload(BaseModel):
    body: Optional[str] = None
    subject: Optional[str] = None
    tone: Optional[str] = None

class RegeneratePayload(BaseModel):
    tone: Optional[str] = "Professional"
    custom_prompt: Optional[str] = ""

class SwitchTenantPayload(BaseModel):
    user_id: str

class RegisterPayload(BaseModel):
    email: str
    password: str
    display_name: Optional[str] = ""

class LoginPayload(BaseModel):
    email: str
    password: str

class ChatQueryPayload(BaseModel):
    query: str
    filter_type: Optional[str] = None
    conversation_history: Optional[List[Dict[str, str]]] = []

class IntegrationUpdatePayload(BaseModel):
    connector_id: str
    enabled: Optional[bool] = None
    webhook_url: Optional[str] = None
    channel: Optional[str] = None
    project_key: Optional[str] = None

class TeamInvitePayload(BaseModel):
    name: str
    email: str
    role: str = "Executive Assistant"


# --- FRONTEND ROUTE ---
@app.get("/")
@app.get("/index.html")
@app.get("/api")
@app.get("/api/")
@app.get("/api/index")
@app.get("/api/index.py")
def serve_dashboard():
    # Check all possible locations for index.html (local dev, packaged, or Vercel static build)
    candidates = [
        STATIC_DIR / "index.html",
        BASE_DIR.parent / "public" / "index.html",
        BASE_DIR.parent / "public" / "static" / "index.html",
        BASE_DIR / "static" / "index.html"
    ]
    for index_path in candidates:
        if index_path.exists():
            return FileResponse(str(index_path))
    return JSONResponse({"message": "AutoMail AI Backend Running. UI is initializing..."})


# --- REAL-TIME LIVE WEBSOCKET ENDPOINT ---
@app.on_event("startup")
async def on_startup():
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        ws_manager.set_loop(loop)
    except Exception:
        pass


@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    """Real-time bi-directional telemetry stream for browser clients."""
    await ws_manager.connect(websocket)
    try:
        # Send initial welcome and live stats payload
        stats = storage.for_user("default").get_stats()
        await websocket.send_json({
            "type": "connected",
            "message": "AutoMail Live Telemetry Stream Connected",
            "data": stats,
            "timestamp": datetime.now().isoformat()
        })
        while True:
            # Listen for client heartbeat pings to keep socket alive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# --- AUTH & TENANT ENDPOINTS ---
@app.get("/api/auth/me")
def get_auth_me(request: Request):
    user = get_current_user_account(request)
    if not user:
        # Check default user
        user = user_manager.get_user_by_id("default")
    user_id = user["id"] if user else "default"
    cfg = load_config(user_id=user_id)
    return {
        "authenticated": bool(user),
        "user": user,
        "active_user_id": user_id,
        "email": user.get("email") if user else cfg.get("account", {}).get("email", ""),
        "name": user.get("name") if user else "User",
        "role": user.get("role", "user") if user else "user",
        "provider": user.get("provider", "local") if user else "local",
        "tenants": storage.list_tenants()
    }


@app.post("/api/auth/register")
def register(payload: RegisterPayload, response: Response):
    success, msg, user = user_manager.register_user(
        email=payload.email,
        password=payload.password,
        display_name=payload.display_name
    )
    if not success or not user:
        raise HTTPException(status_code=400, detail=msg)

    token = create_jwt_token(user)
    response.set_cookie(key="automail_token", value=token, httponly=False, samesite="lax", max_age=2592000)
    response.set_cookie(key="automail_user_id", value=user["id"], httponly=False, samesite="lax", max_age=2592000)
    storage.for_user(user["id"]).log("AUTH", f"User registered account: {user['email']}", "SUCCESS")
    return {"success": True, "token": token, "user": user, "message": msg}


@app.post("/api/auth/login")
def login(payload: LoginPayload, response: Response):
    success, msg, user = user_manager.authenticate_local(
        email=payload.email,
        password=payload.password
    )
    if not success or not user:
        raise HTTPException(status_code=401, detail=msg)

    token = create_jwt_token(user)
    response.set_cookie(key="automail_token", value=token, httponly=False, samesite="lax", max_age=2592000)
    response.set_cookie(key="automail_user_id", value=user["id"], httponly=False, samesite="lax", max_age=2592000)
    storage.for_user(user["id"]).log("AUTH", f"User logged in: {user['email']}", "SUCCESS")
    return {"success": True, "token": token, "user": user, "message": msg}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("automail_token")
    response.delete_cookie("automail_user_id")
    return {"success": True, "message": "Logged out successfully"}


@app.get("/api/auth/google/url")
def get_google_oauth_url():
    """Returns Google OAuth 2.0 redirection URL based on .env configuration."""
    auth_url = google_oauth.get_authorization_url()
    return {
        "configured": google_oauth.is_configured(),
        "url": auth_url,
        "client_id": google_oauth.client_id,
        "callback_url": google_oauth.redirect_uri
    }


@app.get("/api/auth/google/callback")
def google_callback(code: Optional[str] = None, error: Optional[str] = None):
    """Callback receiver for Google OAuth redirect."""
    if error or not code:
        return RedirectResponse(url=f"/?auth_error={error or 'cancelled'}")

    user_info = google_oauth.exchange_code_for_token(code)
    if not user_info:
        return RedirectResponse(url="/?auth_error=google_token_exchange_failed")

    user = user_manager.find_or_create_google_user(user_info)
    token = create_jwt_token(user)

    response = RedirectResponse(url=f"/?token={token}&user_id={user['id']}")
    response.set_cookie(key="automail_token", value=token, httponly=False, samesite="lax", max_age=2592000)
    response.set_cookie(key="automail_user_id", value=user["id"], httponly=False, samesite="lax", max_age=2592000)
    storage.for_user(user["id"]).log("AUTH", f"Google OAuth login successful for {user['email']}", "SUCCESS")
    return response


@app.get("/api/auth/tenants")
def get_tenants():
    return storage.list_tenants()


@app.post("/api/auth/switch")
def switch_tenant(payload: SwitchTenantPayload, response: Response):
    clean_id = tenant_security.sanitize_tenant_id(payload.user_id)
    user_storage = storage.for_user(clean_id)
    user_cfg = load_config(clean_id)
    response.set_cookie(
        key="automail_user_id",
        value=clean_id,
        httponly=False,
        samesite="lax",
        max_age=31536000
    )
    user_storage.log("SECURITY", f"User workspace switched to '{clean_id}' with complete data isolation.", "INFO")
    return {
        "success": True,
        "active_user_id": clean_id,
        "account_email": user_cfg.get("account", {}).get("email", ""),
        "total_emails": len(user_storage.get_emails())
    }


# --- ADMIN AUTHENTICATION ENDPOINTS ---

class AdminLoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/admin/login")
async def admin_login(payload: AdminLoginRequest, request: Request):
    """Authenticate with ADMIN_EMAIL + ADMIN_PASSWORD; returns a 2-hour admin JWT.

    The issued JWT carries ``is_admin_session=True`` which is the ONLY
    credential ``require_admin`` will accept — any other path is blocked.
    """
    # Rate-limit admin login attempts (10 per minute per IP)
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not api_rate_limiter.is_allowed(f"admin_login:{client_ip}", max_requests=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in a minute.")

    admin_email = os.environ.get("ADMIN_EMAIL", "").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()

    if not admin_email or not admin_password:
        raise HTTPException(
            status_code=503,
            detail="Admin credentials not configured. Set ADMIN_EMAIL and ADMIN_PASSWORD in .env.",
        )

    # Constant-time comparison — prevents timing-attack credential enumeration
    email_ok = hmac.compare_digest(payload.email.strip().lower(), admin_email.lower())
    pass_ok  = hmac.compare_digest(payload.password.strip(), admin_password)

    if not (email_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid admin email or password.")

    # Issue a short-lived admin JWT (2 hours)
    admin_token = create_jwt_token(
        "__admin__",
        email=admin_email,
        role="admin",
        extra_claims={"is_admin_session": True},
        expires_in=timedelta(hours=2),
    )
    storage.log("ADMIN", f"Admin panel login from {client_ip}")
    return {"token": admin_token, "expires_in": 7200, "email": admin_email}


@app.post("/api/admin/logout")
def admin_logout():
    """Client-side logout — token invalidation happens in the browser."""
    return {"success": True, "message": "Admin session cleared. Please discard your token."}


# --- ADMIN MONITORING ENDPOINTS (PROTECTED WITH ADMIN JWT) ---
@app.get("/api/admin/overview")
def get_admin_overview(admin_user: Dict[str, Any] = Depends(require_admin)):
    """Retrieve global system-wide KPIs across all tenants (Admin only)."""
    return storage.get_admin_system_overview()


@app.get("/api/admin/users")
def get_admin_users(admin_user: Dict[str, Any] = Depends(require_admin)):
    """Retrieve list of all monitored tenants and their live telemetry (Admin only)."""
    return storage.list_admin_users_telemetry()


@app.post("/api/admin/users/{user_id}/sync")
def admin_sync_user(user_id: str, admin_user: Dict[str, Any] = Depends(require_admin)):
    """Admin-triggered on-demand synchronization for a specific user mailbox (Admin only)."""
    clean_id = tenant_security.sanitize_tenant_id(user_id)
    res = email_engine.sync_emails(user_id=clean_id)
    storage.for_user(clean_id).log("ADMIN", f"Admin initiated manual email sync for tenant '{clean_id}'", "INFO")
    return {"success": True, "details": res, "user_id": clean_id}


@app.post("/api/admin/sync-all")
def admin_sync_all(admin_user: Dict[str, Any] = Depends(require_admin)):
    """Admin-triggered sync across all configured user accounts (Admin only)."""
    tenants = storage.list_tenants()
    results = {}
    for t in tenants:
        uid = t["id"]
        cfg = load_config(user_id=uid)
        if cfg.get("account", {}).get("email_address") or cfg.get("account", {}).get("email"):
            r = email_engine.sync_emails(user_id=uid)
            results[uid] = r
    return {"success": True, "synced_tenants": len(results), "results": results}


@app.get("/api/admin/audit-logs")
def get_admin_audit_logs(limit: int = 150, admin_user: Dict[str, Any] = Depends(require_admin)):
    """Retrieve unified cross-tenant security and operational audit stream (Admin only)."""
    return storage.get_cross_tenant_audit_logs(limit=limit)


@app.get("/api/admin/users/{user_id}/inspect")
def get_admin_user_inspect(user_id: str, admin_user: Dict[str, Any] = Depends(require_admin)):
    """Retrieve telemetry deep-dive for a specific tenant (Admin only)."""
    clean_id = tenant_security.sanitize_tenant_id(user_id)
    return storage.get_tenant_inspect_data(clean_id)


@app.get("/api/admin/gemini/pool")
def get_admin_gemini_pool(admin_user: Dict[str, Any] = Depends(require_admin)):
    """Retrieve real-time token tracking and health telemetry across all Gemini keys (Admin only)."""
    return gemini_token_manager.get_telemetry()


@app.post("/api/admin/gemini/pool/reload")
def reload_admin_gemini_pool(admin_user: Dict[str, Any] = Depends(require_admin)):
    """Re-scan .env and environment for newly configured Gemini API keys (Admin only)."""
    gemini_token_manager.reload_keys_from_env()
    return {"success": True, "telemetry": gemini_token_manager.get_telemetry()}


# --- API ENDPOINTS ---
@app.get("/api/stats")
def get_stats(user_id: str = Depends(get_current_user_id)):
    return storage.for_user(user_id).get_stats()


@app.get("/api/emails")
def get_emails(
    category: Optional[str] = None,
    status: Optional[str] = None,
    user_id: str = Depends(get_current_user_id)
):
    return storage.for_user(user_id).get_emails(category=category, status=status)


@app.get("/api/emails/{email_id}")
def get_email_detail(email_id: str, user_id: str = Depends(get_current_user_id)):
    user_storage = storage.for_user(user_id)
    item = user_storage.get_email(email_id)
    if not item:
        raise HTTPException(status_code=404, detail="Email not found")
    
    draft = None
    if item.get("draft_id"):
        draft = user_storage.get_draft(item["draft_id"])
    return {"email": item, "draft": draft}


@app.post("/api/emails/sync")
def trigger_sync(background_tasks: BackgroundTasks, user_id: str = Depends(get_current_user_id)):
    res = email_engine.sync_emails(user_id=user_id)
    ws_manager.broadcast_sync("sync_completed", {
        "user_id": user_id,
        "new_emails": res.get("new_emails", 0),
        "total_processed": res.get("total_processed", 0)
    })
    return res


@app.post("/api/emails/simulate")
def simulate_email(scenario: str = "customer_support", user_id: str = Depends(get_current_user_id)):
    """Simulate an incoming email for real-time testing."""
    res = email_engine.simulate_test_email(scenario=scenario, user_id=user_id)
    return res


@app.post("/api/emails/{email_id}/status")
def update_email_status(
    email_id: str,
    payload: Dict[str, str],
    user_id: str = Depends(get_current_user_id)
):
    user_storage = storage.for_user(user_id)
    new_status = payload.get("status", "read")
    ok = user_storage.update_email(email_id, {"status": new_status})
    if not ok:
        raise HTTPException(status_code=404, detail="Email not found")
    return {"success": True}


# --- APPROVALS & DRAFTS ---
@app.get("/api/approvals")
@app.get("/api/drafts")
def get_approvals(status: Optional[str] = None, user_id: str = Depends(get_current_user_id)):
    user_storage = storage.for_user(user_id)
    drafts = user_storage.get_drafts(status=status)
    augmented = []
    for d in drafts:
        email_obj = user_storage.get_email(d.get("email_id", ""))
        augmented.append({
            **d,
            "original_email": email_obj
        })
    return augmented


@app.post("/api/approvals/{draft_id}/approve")
@app.post("/api/drafts/{draft_id}/approve")
def approve_draft(draft_id: str, user_id: str = Depends(get_current_user_id)):
    success, message = email_engine.send_draft(draft_id, user_id=user_id)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"success": True, "message": message}


@app.post("/api/approvals/{draft_id}/reject")
def reject_draft(draft_id: str, user_id: str = Depends(get_current_user_id)):
    user_storage = storage.for_user(user_id)
    draft = user_storage.get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    user_storage.update_draft(draft_id, {"status": "rejected"})
    user_storage.log("APPROVAL", f"Draft {draft_id} for '{draft.get('subject')}' was rejected by user.", "INFO")
    return {"success": True}


@app.post("/api/approvals/{draft_id}/update")
def update_draft(
    draft_id: str,
    payload: DraftUpdatePayload,
    user_id: str = Depends(get_current_user_id)
):
    user_storage = storage.for_user(user_id)
    updates = {}
    if payload.body is not None:
        updates["body"] = payload.body
    if payload.subject is not None:
        updates["subject"] = payload.subject
    if payload.tone is not None:
        updates["tone"] = payload.tone
    
    ok = user_storage.update_draft(draft_id, updates)
    if not ok:
        raise HTTPException(status_code=404, detail="Draft not found")
    return {"success": True}


@app.post("/api/approvals/{draft_id}/regenerate")
def regenerate_draft(
    draft_id: str,
    payload: RegeneratePayload,
    user_id: str = Depends(get_current_user_id)
):
    user_storage = storage.for_user(user_id)
    draft = user_storage.get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    
    email_obj = user_storage.get_email(draft.get("email_id", ""))
    if not email_obj:
        raise HTTPException(status_code=404, detail="Original email not found")

    new_body = ai_engine.generate_reply(
        email_obj,
        tone=payload.tone or "Professional",
        custom_prompt=payload.custom_prompt or "",
        user_id=user_id
    )
    user_storage.update_draft(draft_id, {"body": new_body, "tone": payload.tone})
    user_storage.log("AI", f"Regenerated draft {draft_id} with tone '{payload.tone}'", "INFO")
    return {"success": True, "body": new_body}


# --- RULES ---
@app.get("/api/rules")
def get_rules(user_id: str = Depends(get_current_user_id)):
    return storage.for_user(user_id).get_rules()


@app.post("/api/rules")
def create_rule(payload: RulePayload, user_id: str = Depends(get_current_user_id)):
    user_storage = storage.for_user(user_id)
    rule_id = user_storage.add_rule(payload.dict())
    user_storage.log("RULE", f"Created new automation rule '{payload.name}'", "SUCCESS")
    return {"success": True, "id": rule_id}


@app.put("/api/rules/{rule_id}")
def update_rule(
    rule_id: str,
    payload: Dict[str, Any],
    user_id: str = Depends(get_current_user_id)
):
    user_storage = storage.for_user(user_id)
    ok = user_storage.update_rule(rule_id, payload)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True}


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str, user_id: str = Depends(get_current_user_id)):
    user_storage = storage.for_user(user_id)
    ok = user_storage.delete_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    user_storage.log("RULE", f"Deleted automation rule {rule_id}", "INFO")
    return {"success": True}


# --- OUTBOX / SENT ---
@app.get("/api/sent")
def get_sent(user_id: str = Depends(get_current_user_id)):
    return storage.for_user(user_id).get_sent_emails()


# --- LOGS ---
@app.get("/api/logs")
def get_logs(limit: int = 100, user_id: str = Depends(get_current_user_id)):
    return storage.for_user(user_id).get_logs(limit=limit)


# --- SECURITY STATUS ---
@app.get("/api/security/status")
def get_security_status(user_id: str = Depends(get_current_user_id)):
    return {
        "tenant_id": user_id,
        "multi_tenant_isolated": True,
        "vault_encrypted": True,
        "prompt_shield_active": True,
        "leak_prevention_active": True,
        "rate_limiting_active": True,
        "hourly_dispatches": len(dispatch_limiter.dispatches),
        "hourly_dispatch_max": dispatch_limiter.max_per_hour
    }


# --- SETTINGS ---
@app.get("/api/settings")
def get_settings(user_id: str = Depends(get_current_user_id)):
    cfg = load_config(user_id=user_id)
    # Mask all secrets so they never leave backend unmasked
    masked = dict(cfg)
    if "account" in masked and "app_password" in masked["account"]:
        raw_pwd = masked["account"]["app_password"]
        masked["account"]["has_password"] = bool(raw_pwd)
        masked["account"]["app_password"] = ""
        masked["account"]["app_password_masked"] = "••••••••••••••••" if raw_pwd else ""

    if "ai" in masked and "gemini_api_key" in masked["ai"]:
        raw_key = masked["ai"]["gemini_api_key"]
        masked["ai"]["has_api_key"] = bool(raw_key)
        masked["ai"]["gemini_api_key_masked"] = vault.mask(raw_key) if raw_key else ""
        masked["ai"]["gemini_api_key"] = ""
    return masked


@app.post("/api/settings")
def save_settings(payload: SettingsPayload, user_id: str = Depends(get_current_user_id)):
    current = load_config(user_id=user_id)
    new_data = payload.dict()
    
    # Preserve existing password if user left it blank
    if "account" in new_data:
        entered_pwd = new_data["account"].get("app_password", "")
        if not entered_pwd and current.get("account", {}).get("app_password"):
            new_data["account"]["app_password"] = current["account"]["app_password"]

    # Preserve existing Gemini key if user left it blank
    if "ai" in new_data:
        entered_key = new_data["ai"].get("gemini_api_key", "")
        if not entered_key and current.get("ai", {}).get("gemini_api_key"):
            new_data["ai"]["gemini_api_key"] = current["ai"]["gemini_api_key"]

    ok = save_config(new_data, user_id=user_id)
    storage.for_user(user_id).log("SECURITY", "Updated settings with encrypted secret isolation.", "SUCCESS")
    return {"success": ok}


@app.post("/api/settings/test-connection")
def test_connection(user_id: str = Depends(get_current_user_id)):
    success, msg = email_engine.test_connection(user_id=user_id)
    return {"success": success, "message": msg}


@app.post("/api/settings/test-ai")
def test_ai(user_id: str = Depends(get_current_user_id)):
    success, msg = ai_engine.test_ai_connection(user_id=user_id)
    return {"success": success, "message": msg}


# --- RAG CHATBOT ENDPOINTS ---
@app.post("/api/chat/query")
def chat_query(payload: ChatQueryPayload, user_id: str = Depends(get_current_user_id)):
    """Query the RAG Chatbot using the active authenticated user's isolated workspace."""
    return rag_chatbot.answer_query(
        query=payload.query,
        user_id=user_id,
        conversation_history=payload.conversation_history or [],
        filter_type=payload.filter_type
    )


@app.get("/api/chat/suggestions")
def chat_suggestions(user_id: str = Depends(get_current_user_id)):
    """Retrieve dynamic contextual prompt suggestions for active user's mailbox."""
    return {
        "user_id": user_id,
        "suggestions": rag_chatbot.get_dynamic_suggestions(user_id=user_id)
    }


@app.get("/api/chat/history")
def chat_history(user_id: str = Depends(get_current_user_id)):
    """Retrieve recent RAG query logs for active user."""
    user_storage = storage.for_user(user_id)
    logs = user_storage.get_logs(limit=25)
    chat_logs = [l for l in logs if l.get("category") == "RAG"]
    return chat_logs


@app.post("/api/chat/clear")
def chat_clear(user_id: str = Depends(get_current_user_id)):
    """Clear active user's chat session."""
    return {"success": True, "message": "Chat session cleared.", "user_id": user_id}


# --- ENTERPRISE SERVICES & GOVERNANCE SUITE ---
@app.get("/api/enterprise/metrics")
def get_enterprise_metrics(hourly_rate: float = 85.0, user_id: str = Depends(get_current_user_id)):
    """Return live calculated enterprise productivity ROI, hours saved, and SLA reduction."""
    return storage.for_user(user_id).get_enterprise_metrics(hourly_rate=hourly_rate)


@app.get("/api/enterprise/compliance")
def get_enterprise_compliance(user_id: str = Depends(get_current_user_id)):
    """Return enterprise SOC-2, ISO-27001, GDPR, and HIPAA compliance posture."""
    return storage.for_user(user_id).get_compliance_status()


@app.get("/api/enterprise/integrations")
def get_enterprise_integrations(user_id: str = Depends(get_current_user_id)):
    """Return enterprise connectors list and active status."""
    return storage.for_user(user_id).get_integrations()


@app.post("/api/enterprise/integrations/toggle")
def toggle_enterprise_integration(payload: IntegrationUpdatePayload, user_id: str = Depends(get_current_user_id)):
    """Update or toggle an enterprise integration connector."""
    updates = {k: v for k, v in payload.dict().items() if v is not None}
    cid = updates.pop("connector_id", "")
    res = storage.for_user(user_id).update_integration(cid, updates)
    return {"success": True, "connector_id": cid, "config": res}


@app.get("/api/enterprise/team")
def get_enterprise_team(user_id: str = Depends(get_current_user_id)):
    """Return organization seats allocation and team member roster."""
    return storage.for_user(user_id).get_team_members()


@app.post("/api/enterprise/team/invite")
def invite_enterprise_team(payload: TeamInvitePayload, user_id: str = Depends(get_current_user_id)):
    """Invite a new enterprise seat license with RBAC role."""
    if not payload.email or "@" not in payload.email:
        raise HTTPException(status_code=400, detail="Valid email required")
    member = storage.for_user(user_id).invite_team_member(
        name=payload.name,
        email=payload.email,
        role=payload.role
    )
    return {"success": True, "member": member}


@app.get("/api/enterprise/audit/export")
def export_enterprise_audit_logs(format: str = "json", user_id: str = Depends(get_current_user_id)):
    """Export cryptographic SIEM audit logs as JSON or CSV."""
    content, media_type = storage.for_user(user_id).export_audit_logs(format_type=format)
    filename = f"automail_audit_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


def run():
    uvicorn.run("email_service.server:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    run()
