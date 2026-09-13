"""
Local state and storage manager for Email Automation Service.
Provides persistent storage for emails, AI reply drafts, automation rules,
sent outbox history, and live activity logs.
"""

import os
import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import threading

DATA_DIR = Path(__file__).parent / "data"
STATE_FILE = DATA_DIR / "state.json"
_lock = threading.Lock()

DEFAULT_RULES = [
    {
        "id": "rule_urgent_client",
        "name": "Auto-Flag Urgent Inquiries",
        "enabled": True,
        "condition_field": "subject",
        "condition_operator": "contains",
        "condition_value": "urgent",
        "action": "mark_urgent",
        "action_param": "Urgent"
    },
    {
        "id": "rule_invoice_billing",
        "name": "Classify Invoices & Billing",
        "enabled": True,
        "condition_field": "subject",
        "condition_operator": "contains",
        "condition_value": "invoice",
        "action": "set_category",
        "action_param": "Billing/Invoice"
    },
    {
        "id": "rule_sales_inquiry",
        "name": "Auto-Draft Sales Replies",
        "enabled": True,
        "condition_field": "category",
        "condition_operator": "equals",
        "condition_value": "Sales Inquiry",
        "action": "auto_draft",
        "action_param": "Friendly"
    },
    {
        "id": "rule_support_inquiry",
        "name": "Auto-Draft Support Replies",
        "enabled": True,
        "condition_field": "category",
        "condition_operator": "equals",
        "condition_value": "Customer Support",
        "action": "auto_draft",
        "action_param": "Professional"
    }
]

INITIAL_SAMPLE_EMAILS = [
    {
        "id": "msg_sample_01",
        "uid": "1001",
        "from": "Elena Rostova <elena.rostova@acmepartners.com>",
        "sender_name": "Elena Rostova",
        "sender_organization": "Acme Partners",
        "to": "you@domain.com",
        "subject": "Urgent: Contract clarification for Q4 Partnership agreement",
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "snippet": "Hi, we are reviewing Section 4.2 of the partnership contract regarding API rate limits and need...",
        "body": "Hi there,\n\nWe are reviewing Section 4.2 of the partnership contract regarding API rate limits and service tier uptime guarantees.\nCould you clarify if enterprise support includes 24/7 dedicated escalation channels?\n\nWe would appreciate a response by tomorrow morning so we can finalize signatures.\n\nBest regards,\nElena Rostova\nVP of Partnerships, Acme Partners",
        "category": "Urgent Action",
        "priority": "Urgent",
        "sentiment": "Neutral",
        "summary": "Elena asks for urgent clarification on contract Section 4.2 regarding enterprise 24/7 escalation before signing tomorrow.",
        "compressed_summary": "Elena Rostova (Acme Partners) needs clarification on whether enterprise support in Section 4.2 includes 24/7 dedicated escalation before signing tomorrow morning.",
        "core_intent": "Contract SLA Clarification",
        "action_needed": True,
        "status": "unread",
        "draft_id": "draft_sample_01",
        "tasks": [
            "Clarify if enterprise support includes 24/7 dedicated escalation channels",
            "Confirm SLA response time guarantee",
            "Provide response before tomorrow morning for contract signing"
        ],
        "ai_automated_actions": [
            "Ingested & analyzed by AI engine",
            "Extracted 3 action items for owner",
            "Auto-drafted response confirming Section 4.2 SLA",
            "Queued in Approval Center for 1-click execution"
        ],
        "created_at": datetime.now().isoformat()
    },
    {
        "id": "msg_sample_02",
        "uid": "1002",
        "from": "Marcus Vance <mvance@quantumcloud.io>",
        "sender_name": "Marcus Vance",
        "sender_organization": "QuantumCloud",
        "to": "you@domain.com",
        "subject": "Demo Request: Exploring AI Automation for our Operations",
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "snippet": "Hello! I saw your recent updates on autonomous email automation and workflow assistants...",
        "body": "Hello,\n\nI saw your recent updates on autonomous email automation and workflow assistants. Our team handles around 400 incoming customer inquiries every week, and we'd love to schedule a 20-minute product demo.\n\nDo you have availability this Thursday or Friday afternoon?\n\nThanks,\nMarcus Vance\nHead of Operations, QuantumCloud",
        "category": "Sales Inquiry",
        "priority": "High",
        "sentiment": "Positive",
        "summary": "Marcus Vance requests a 20-minute demo for email automation this Thursday or Friday afternoon.",
        "compressed_summary": "Marcus Vance (QuantumCloud) is requesting a 20-minute product demo for AI email automation with availability on Thursday or Friday afternoon.",
        "core_intent": "Product Demo Request",
        "action_needed": True,
        "status": "unread",
        "draft_id": "draft_sample_02",
        "tasks": [
            "Schedule 20-minute email automation product demo",
            "Provide team availability for Thursday or Friday afternoon"
        ],
        "ai_automated_actions": [
            "Ingested & analyzed by AI engine",
            "Identified sales opportunity for 400+ weekly inquiries",
            "Drafted calendar availability response",
            "Queued for owner review"
        ],
        "created_at": datetime.now().isoformat()
    }
]

INITIAL_SAMPLE_DRAFTS = [
    {
        "id": "draft_sample_01",
        "email_id": "msg_sample_01",
        "recipient": "Elena Rostova <elena.rostova@acmepartners.com>",
        "subject": "Re: Urgent: Contract clarification for Q4 Partnership agreement",
        "body": "Dear Elena,\n\nThank you for reaching out. Yes, Section 4.2 enterprise support specifically guarantees 24/7 dedicated escalation channels with a 30-minute priority response SLA.\n\nI have confirmed this with our legal and technical teams. Please let me know if you need any supplemental addendums prior to signing.\n\nBest regards,\nExecutive Team",
        "tone": "Professional",
        "status": "pending",
        "created_at": datetime.now().isoformat(),
        "reviewed_at": None,
        "sent_at": None
    },
    {
        "id": "draft_sample_02",
        "email_id": "msg_sample_02",
        "recipient": "Marcus Vance <mvance@quantumcloud.io>",
        "subject": "Re: Demo Request: Exploring AI Automation for our Operations",
        "body": "Hi Marcus,\n\nThank you for getting in touch! We'd be thrilled to demonstrate how our email automation service can streamline your 400+ weekly inquiries.\n\nThursday at 2:00 PM EST or Friday at 11:00 AM EST works great on our end. Would either of those slots suit your team?\n\nLooking forward to speaking soon.\n\nWarm regards,\nSales & Solutions Team",
        "tone": "Friendly",
        "status": "pending",
        "created_at": datetime.now().isoformat(),
        "reviewed_at": None,
        "sent_at": None
    }
]


class StorageManager:
    def __init__(self, user_id: str = "default"):
        from .security import tenant_security
        self.user_id = tenant_security.sanitize_tenant_id(user_id)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        
        if self.user_id == "default":
            self.state_file = STATE_FILE
        else:
            tenant_dir = DATA_DIR / "tenants" / self.user_id
            tenant_dir.mkdir(parents=True, exist_ok=True)
            self.state_file = tenant_dir / "state.json"
            
        self._load()

    def _get_initial_state(self) -> Dict[str, Any]:
        if self.user_id == "default":
            return {
                "emails": {e["id"]: e for e in INITIAL_SAMPLE_EMAILS},
                "drafts": {d["id"]: d for d in INITIAL_SAMPLE_DRAFTS},
                "rules": DEFAULT_RULES,
                "sent_emails": [],
                "logs": [
                    {
                        "id": str(uuid.uuid4())[:8],
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "level": "SUCCESS",
                        "category": "SYSTEM",
                        "message": "Email Automation Service initialized successfully."
                    },
                    {
                        "id": str(uuid.uuid4())[:8],
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "level": "INFO",
                        "category": "AI",
                        "message": "Loaded 2 pending sample emails with AI-drafted responses ready for review."
                    }
                ],
                "last_sync_time": datetime.now().isoformat(),
                "last_uid": 1002
            }
        else:
            return {
                "emails": {},
                "drafts": {},
                "rules": [dict(r) for r in DEFAULT_RULES],
                "sent_emails": [],
                "logs": [
                    {
                        "id": str(uuid.uuid4())[:8],
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "level": "SUCCESS",
                        "category": "SECURITY",
                        "message": f"Secure tenant workspace for '{self.user_id}' initialized with zero cross-user leakage."
                    }
                ],
                "last_sync_time": "Never",
                "last_uid": 0
            }

    def _load(self):
        with _lock:
            if not self.state_file.exists():
                self.state = self._get_initial_state()
                self._save_unlocked()
            else:
                try:
                    with open(self.state_file, "r", encoding="utf-8") as f:
                        self.state = json.load(f)
                except Exception as e:
                    print(f"Error reading state file for user '{self.user_id}': {e}. Reinitializing.")
                    self.state = self._get_initial_state()
                    self._save_unlocked()

    def _save_unlocked(self):
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving state for user '{self.user_id}': {e}")

    def save(self):
        with _lock:
            self._save_unlocked()

    # --- EMAILS ---
    def get_emails(self, category: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with _lock:
            emails = list(self.state.get("emails", {}).values())
            # Sort newest first
            emails.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            if category and category != "All":
                emails = [e for e in emails if e.get("category") == category]
            if status:
                emails = [e for e in emails if e.get("status") == status]
            return emails

    def get_email(self, email_id: str) -> Optional[Dict[str, Any]]:
        with _lock:
            return self.state.get("emails", {}).get(email_id)

    def add_email(self, email_data: Dict[str, Any]) -> str:
        with _lock:
            if "id" not in email_data:
                email_data["id"] = f"msg_{uuid.uuid4().hex[:8]}"
            if "created_at" not in email_data:
                email_data["created_at"] = datetime.now().isoformat()
            
            self.state.setdefault("emails", {})[email_data["id"]] = email_data
            self._save_unlocked()
            return email_data["id"]

    def update_email(self, email_id: str, updates: Dict[str, Any]) -> bool:
        with _lock:
            if email_id in self.state.get("emails", {}):
                self.state["emails"][email_id].update(updates)
                self._save_unlocked()
                return True
            return False

    # --- DRAFTS & APPROVALS ---
    def get_drafts(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with _lock:
            drafts = list(self.state.get("drafts", {}).values())
            drafts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            if status:
                drafts = [d for d in drafts if d.get("status") == status]
            return drafts

    def get_draft(self, draft_id: str) -> Optional[Dict[str, Any]]:
        with _lock:
            return self.state.get("drafts", {}).get(draft_id)

    def add_draft(self, draft_data: Dict[str, Any]) -> str:
        with _lock:
            if "id" not in draft_data:
                draft_data["id"] = f"draft_{uuid.uuid4().hex[:8]}"
            if "created_at" not in draft_data:
                draft_data["created_at"] = datetime.now().isoformat()
            if "status" not in draft_data:
                draft_data["status"] = "pending"
                
            self.state.setdefault("drafts", {})[draft_data["id"]] = draft_data
            
            # Associate with email
            email_id = draft_data.get("email_id")
            if email_id and email_id in self.state.get("emails", {}):
                self.state["emails"][email_id]["draft_id"] = draft_data["id"]
                
            self._save_unlocked()
            return draft_data["id"]

    def update_draft(self, draft_id: str, updates: Dict[str, Any]) -> bool:
        with _lock:
            if draft_id in self.state.get("drafts", {}):
                self.state["drafts"][draft_id].update(updates)
                self._save_unlocked()
                return True
            return False

    # --- RULES ---
    def get_rules(self) -> List[Dict[str, Any]]:
        with _lock:
            return self.state.get("rules", [])

    def add_rule(self, rule_data: Dict[str, Any]) -> str:
        with _lock:
            if "id" not in rule_data:
                rule_data["id"] = f"rule_{uuid.uuid4().hex[:6]}"
            self.state.setdefault("rules", []).append(rule_data)
            self._save_unlocked()
            return rule_data["id"]

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        with _lock:
            rules = self.state.get("rules", [])
            for r in rules:
                if r.get("id") == rule_id:
                    r.update(updates)
                    self._save_unlocked()
                    return True
            return False

    def delete_rule(self, rule_id: str) -> bool:
        with _lock:
            rules = self.state.get("rules", [])
            new_rules = [r for r in rules if r.get("id") != rule_id]
            if len(new_rules) != len(rules):
                self.state["rules"] = new_rules
                self._save_unlocked()
                return True
            return False

    # --- SENT EMAILS ---
    def add_sent_email(self, sent_record: Dict[str, Any]) -> str:
        with _lock:
            if "id" not in sent_record:
                sent_record["id"] = f"sent_{uuid.uuid4().hex[:8]}"
            if "sent_at" not in sent_record:
                sent_record["sent_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.state.setdefault("sent_emails", []).insert(0, sent_record)
            self._save_unlocked()
            return sent_record["id"]

    def get_sent_emails(self) -> List[Dict[str, Any]]:
        with _lock:
            return self.state.get("sent_emails", [])

    # --- LOGS ---
    def log(self, category: str, message: str, level: str = "INFO", details: Optional[Dict[str, Any]] = None):
        with _lock:
            entry = {
                "id": str(uuid.uuid4())[:8],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "level": level.upper(),
                "category": category.upper(),
                "message": message,
                "details": details or {}
            }
            logs = self.state.setdefault("logs", [])
            logs.insert(0, entry)
            # Cap logs to 500 items
            if len(logs) > 500:
                self.state["logs"] = logs[:500]
            self._save_unlocked()

    def get_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with _lock:
            return self.state.get("logs", [])[:limit]

    # --- STATS ---
    def get_stats(self) -> Dict[str, Any]:
        with _lock:
            emails = list(self.state.get("emails", {}).values())
            drafts = list(self.state.get("drafts", {}).values())
            sent = self.state.get("sent_emails", [])
            rules = self.state.get("rules", [])
            
            pending_approvals = [d for d in drafts if d.get("status") == "pending"]
            urgent_emails = [e for e in emails if e.get("priority") in ["Urgent", "High"]]
            
            return {
                "total_emails": len(emails),
                "unread_emails": len([e for e in emails if e.get("status") == "unread"]),
                "pending_approvals": len(pending_approvals),
                "sent_count": len(sent),
                "active_rules": len([r for r in rules if r.get("enabled", True)]),
                "urgent_count": len(urgent_emails),
                "last_sync_time": self.state.get("last_sync_time", "Never")
            }


_storage_cache: Dict[str, StorageManager] = {}
_cache_lock = threading.Lock()

def get_storage(user_id: str = "default") -> StorageManager:
    """Retrieve or create the isolated StorageManager instance for a tenant."""
    from .security import tenant_security
    clean_id = tenant_security.sanitize_tenant_id(user_id)
    with _cache_lock:
        if clean_id not in _storage_cache:
            _storage_cache[clean_id] = StorageManager(user_id=clean_id)
        return _storage_cache[clean_id]


class StorageProxy:
    """Provides backward-compatible attribute access to default storage and .for_user(user_id)."""
    def __getattr__(self, name):
        return getattr(get_storage("default"), name)

    def for_user(self, user_id: str) -> StorageManager:
        return get_storage(user_id)

    def list_tenants(self) -> List[Dict[str, Any]]:
        tenants = [{"id": "default", "name": "Default Account (Admin)", "active": True}]
        tenant_dir = DATA_DIR / "tenants"
        if tenant_dir.exists():
            for d in tenant_dir.iterdir():
                if d.is_dir() and d.name != "default":
                    tenants.append({
                        "id": d.name,
                        "name": f"Account: {d.name}",
                        "active": False
                    })
        return tenants


storage = StorageProxy()
