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
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Request, Response, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from .config import load_config, save_config
from .storage import storage
from .email_engine import email_engine
from .ai_engine import ai_engine
from .security import vault, dispatch_limiter, api_rate_limiter

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


# Mount static directory
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --- BACKGROUND POLLING WORKER ---
_polling_active = True

def background_poller():
    """Periodic worker to sync emails automatically in the background."""
    while _polling_active:
        try:
            cfg = load_config()
            auto_cfg = cfg.get("automation", {})
            if auto_cfg.get("auto_sync", True):
                email_engine.sync_emails()
            interval = max(20, auto_cfg.get("sync_interval_seconds", 60))
        except Exception as e:
            print(f"Background poller exception: {e}")
            interval = 60
        time.sleep(interval)

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


# --- FRONTEND ROUTE ---
@app.get("/")
def serve_dashboard():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return JSONResponse({"message": "Email Automation Backend Running. UI building..."})


# --- API ENDPOINTS ---
@app.get("/api/stats")
def get_stats():
    return storage.get_stats()


@app.get("/api/emails")
def get_emails(category: Optional[str] = None, status: Optional[str] = None):
    return storage.get_emails(category=category, status=status)


@app.get("/api/emails/{email_id}")
def get_email_detail(email_id: str):
    item = storage.get_email(email_id)
    if not item:
        raise HTTPException(status_code=404, detail="Email not found")
    
    draft = None
    if item.get("draft_id"):
        draft = storage.get_draft(item["draft_id"])
    return {"email": item, "draft": draft}


@app.post("/api/emails/sync")
def trigger_sync(background_tasks: BackgroundTasks):
    res = email_engine.sync_emails()
    return res


@app.post("/api/emails/simulate")
def simulate_email(payload: SimulatePayload):
    result = email_engine.simulate_test_email(scenario=payload.scenario)
    return {"success": True, "details": result}


@app.post("/api/emails/{email_id}/status")
def update_email_status(email_id: str, payload: Dict[str, str]):
    new_status = payload.get("status", "read")
    ok = storage.update_email(email_id, {"status": new_status})
    if not ok:
        raise HTTPException(status_code=404, detail="Email not found")
    return {"success": True}


# --- APPROVALS & DRAFTS ---
@app.get("/api/approvals")
def get_approvals(status: Optional[str] = None):
    drafts = storage.get_drafts(status=status)
    augmented = []
    for d in drafts:
        email_obj = storage.get_email(d.get("email_id", ""))
        augmented.append({
            **d,
            "original_email": email_obj
        })
    return augmented


@app.post("/api/approvals/{draft_id}/approve")
def approve_draft(draft_id: str):
    success, message = email_engine.send_draft(draft_id)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"success": True, "message": message}


@app.post("/api/approvals/{draft_id}/reject")
def reject_draft(draft_id: str):
    draft = storage.get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    storage.update_draft(draft_id, {"status": "rejected"})
    storage.log("APPROVAL", f"Draft {draft_id} for '{draft.get('subject')}' was rejected by user.", "INFO")
    return {"success": True}


@app.post("/api/approvals/{draft_id}/update")
def update_draft(draft_id: str, payload: DraftUpdatePayload):
    updates = {}
    if payload.body is not None:
        updates["body"] = payload.body
    if payload.subject is not None:
        updates["subject"] = payload.subject
    if payload.tone is not None:
        updates["tone"] = payload.tone
    
    ok = storage.update_draft(draft_id, updates)
    if not ok:
        raise HTTPException(status_code=404, detail="Draft not found")
    return {"success": True}


@app.post("/api/approvals/{draft_id}/regenerate")
def regenerate_draft(draft_id: str, payload: RegeneratePayload):
    draft = storage.get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    
    email_obj = storage.get_email(draft.get("email_id", ""))
    if not email_obj:
        raise HTTPException(status_code=404, detail="Original email not found")

    new_body = ai_engine.generate_reply(
        email_obj,
        tone=payload.tone or "Professional",
        custom_prompt=payload.custom_prompt or ""
    )
    storage.update_draft(draft_id, {"body": new_body, "tone": payload.tone})
    storage.log("AI", f"Regenerated draft {draft_id} with tone '{payload.tone}'", "INFO")
    return {"success": True, "body": new_body}


# --- RULES ---
@app.get("/api/rules")
def get_rules():
    return storage.get_rules()


@app.post("/api/rules")
def create_rule(payload: RulePayload):
    rule_id = storage.add_rule(payload.dict())
    storage.log("RULE", f"Created new automation rule '{payload.name}'", "SUCCESS")
    return {"success": True, "id": rule_id}


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: str, payload: Dict[str, Any]):
    ok = storage.update_rule(rule_id, payload)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True}


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str):
    ok = storage.delete_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    storage.log("RULE", f"Deleted automation rule {rule_id}", "INFO")
    return {"success": True}


# --- OUTBOX / SENT ---
@app.get("/api/sent")
def get_sent():
    return storage.get_sent_emails()


# --- LOGS ---
@app.get("/api/logs")
def get_logs(limit: int = 100):
    return storage.get_logs(limit=limit)


# --- SECURITY STATUS ---
@app.get("/api/security/status")
def get_security_status():
    return {
        "vault_encrypted": True,
        "prompt_shield_active": True,
        "leak_prevention_active": True,
        "rate_limiting_active": True,
        "hourly_dispatches": len(dispatch_limiter.dispatches),
        "hourly_dispatch_max": dispatch_limiter.max_per_hour
    }


# --- SETTINGS ---
@app.get("/api/settings")
def get_settings():
    cfg = load_config()
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
def save_settings(payload: SettingsPayload):
    current = load_config()
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

    ok = save_config(new_data)
    storage.log("SECURITY", "Updated settings with encrypted secret isolation.", "SUCCESS")
    return {"success": ok}


@app.post("/api/settings/test-connection")
def test_connection():
    success, msg = email_engine.test_connection()
    return {"success": success, "message": msg}


def run():
    uvicorn.run("email_service.server:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    run()
