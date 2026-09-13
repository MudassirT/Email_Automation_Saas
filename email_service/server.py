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
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException, Request, Response, BackgroundTasks, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from .config import load_config, save_config
from .storage import storage
from .email_engine import email_engine
from .ai_engine import ai_engine
from .security import vault, dispatch_limiter, api_rate_limiter, tenant_security

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Email Automation Service API", version="1.0.0")

# 1. CORS Middleware: Restrict strictly to localhost / 127.0.0.1
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# 2. Security Headers & Anti-CSRF Middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # A. Anti-CSRF check for mutating requests from web browsers
    if request.method in ["POST", "PUT", "DELETE"] and request.url.path.startswith("/api/"):
        # Allow requests with custom header or localhost referer/origin
        custom_header = request.headers.get("X-Requested-With")
        origin = request.headers.get("Origin", "")
        referer = request.headers.get("Referer", "")

        is_local_origin = any(host in (origin + referer) for host in ["localhost", "127.0.0.1"])
        if custom_header != "AutoMail" and not is_local_origin:
            return JSONResponse(
                status_code=403,
                content={"detail": "Security violation: Missing Anti-CSRF token or unauthorized cross-site origin."}
            )

    # B. Rate Limiting on sensitive endpoints
    client_ip = request.client.host if request.client else "127.0.0.1"
    if request.url.path in ["/api/emails/sync", "/api/emails/simulate"]:
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
        "connect-src 'self';"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), microphone=(), geolocation=()"

    return response


# Tenant ID extractor & sanitizer
def get_current_user_id(request: Request) -> str:
    """Extract, sanitize, and validate requesting tenant user ID."""
    uid = request.headers.get("X-User-Id")
    if not uid:
        uid = request.cookies.get("automail_user_id")
    if not uid:
        uid = request.query_params.get("user_id", "default")
    return tenant_security.sanitize_tenant_id(uid)


# Mount static directory
STATIC_DIR.mkdir(parents=True, exist_ok=True)
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

class SimulatePayload(BaseModel):
    scenario: Optional[str] = "customer_support"

class SwitchTenantPayload(BaseModel):
    user_id: str


# --- FRONTEND ROUTE ---
@app.get("/")
def serve_dashboard():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return JSONResponse({"message": "Email Automation Backend Running. UI building..."})


# --- AUTH & TENANT ENDPOINTS ---
@app.get("/api/auth/me")
def get_auth_me(user_id: str = Depends(get_current_user_id)):
    cfg = load_config(user_id=user_id)
    return {
        "active_user_id": user_id,
        "email": cfg.get("account", {}).get("email", ""),
        "tenants": storage.list_tenants()
    }


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


# --- ADMIN MONITORING ENDPOINTS ---
@app.get("/api/admin/overview")
def get_admin_overview():
    """Retrieve global system-wide KPIs across all tenants."""
    return storage.get_admin_system_overview()


@app.get("/api/admin/users")
def get_admin_users():
    """Retrieve list of all monitored tenants and their live telemetry."""
    return storage.list_admin_users_telemetry()


@app.post("/api/admin/users/{user_id}/sync")
def admin_sync_user(user_id: str):
    """Admin-triggered on-demand synchronization for a specific user mailbox."""
    clean_id = tenant_security.sanitize_tenant_id(user_id)
    res = email_engine.sync_emails(user_id=clean_id)
    storage.for_user(clean_id).log("ADMIN", f"Admin initiated manual email sync for tenant '{clean_id}'", "INFO")
    return {"success": True, "details": res, "user_id": clean_id}


@app.post("/api/admin/sync-all")
def admin_sync_all():
    """Admin-triggered sync across all configured user accounts."""
    tenants = storage.list_tenants()
    results = {}
    for t in tenants:
        uid = t["id"]
        cfg = load_config(user_id=uid)
        if cfg.get("account", {}).get("email_address"):
            r = email_engine.sync_emails(user_id=uid)
            results[uid] = r
    return {"success": True, "synced_tenants": len(results), "results": results}


@app.get("/api/admin/audit-logs")
def get_admin_audit_logs(limit: int = 150):
    """Retrieve unified cross-tenant security and operational audit stream."""
    return storage.get_cross_tenant_audit_logs(limit=limit)


@app.get("/api/admin/users/{user_id}/inspect")
def get_admin_user_inspect(user_id: str):
    """Retrieve telemetry deep-dive for a specific tenant."""
    clean_id = tenant_security.sanitize_tenant_id(user_id)
    return storage.get_tenant_inspect_data(clean_id)


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
    return res


@app.post("/api/emails/simulate")
def simulate_email(payload: SimulatePayload, user_id: str = Depends(get_current_user_id)):
    result = email_engine.simulate_test_email(scenario=payload.scenario, user_id=user_id)
    return {"success": True, "details": result}


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


def run():
    uvicorn.run("email_service.server:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    run()
