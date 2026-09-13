"""
Configuration manager for Email Automation Service.
Handles settings persistence (IMAP, SMTP, Gmail API, Gemini/AI, Automation rules)
with encrypted-at-rest credential storage.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any

from .security import vault

def get_data_dir() -> Path:
    custom = os.getenv("AUTOMAIL_DATA_DIR")
    p = Path(custom) if custom else Path(__file__).parent / "data"
    p.mkdir(parents=True, exist_ok=True)
    return p

DATA_DIR = get_data_dir()
CONFIG_FILE = DATA_DIR / "config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "account": {
        "email_address": "",
        "app_password": "",
        "imap_server": "imap.gmail.com",
        "imap_port": 993,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "connection_type": "app_password",  # 'app_password' or 'oauth'
        "credentials_path": "",
    },
    "ai": {
        "provider": "gemini",  # 'gemini' or 'built_in'
        "gemini_api_key": "",
        "model_name": "gemini-1.5-flash",
        "default_tone": "Professional",  # 'Professional', 'Friendly', 'Direct', 'Executive'
        "system_instructions": (
            "You are an AI Email Assistant for a professional executive. "
            "Write helpful, polite, and concise email responses. "
            "Address questions directly and provide clear next steps."
        ),
    },
    "automation": {
        "mode": "review_required",  # 'review_required', 'autonomous', or 'draft_only'
        "auto_sync": True,
        "sync_interval_seconds": 60,
        "notify_urgent": True,
        "auto_categorize": True,
        "auto_draft": True,
    }
}


def get_tenant_config_path(user_id: str = "default") -> Path:
    """Resolve isolated configuration file path for the given tenant."""
    from .security import tenant_security
    clean_id = tenant_security.sanitize_tenant_id(user_id)
    data_dir = get_data_dir()
    if clean_id == "default":
        return data_dir / "config.json"
    tenant_dir = data_dir / "tenants" / clean_id
    tenant_dir.mkdir(parents=True, exist_ok=True)
    return tenant_dir / "config.json"


def load_config(user_id: str = "default") -> Dict[str, Any]:
    """Load configuration from disk for a specific tenant, decrypting sensitive secrets."""
    get_data_dir().mkdir(parents=True, exist_ok=True)
    config_path = get_tenant_config_path(user_id)
    
    if not config_path.exists():
        save_config(DEFAULT_CONFIG, user_id=user_id)
        return DEFAULT_CONFIG.copy()
        
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            for k, v in data.items():
                if isinstance(v, dict) and k in merged and isinstance(merged[k], dict):
                    merged[k] = {**merged[k], **v}
                else:
                    merged[k] = v

            # Decrypt secrets
            if "account" in merged:
                raw_pwd = merged["account"].get("app_password", "")
                if raw_pwd and raw_pwd.startswith("ENC::"):
                    merged["account"]["app_password"] = vault.decrypt(raw_pwd)

            if "ai" in merged:
                raw_key = merged["ai"].get("gemini_api_key", "")
                if raw_key and raw_key.startswith("ENC::"):
                    merged["ai"]["gemini_api_key"] = vault.decrypt(raw_key)

            # Environment variable overrides (only apply to default tenant)
            if user_id == "default":
                env_user = os.getenv("GMAIL_USER") or os.getenv("GMAIL_ADDRESS")
                if env_user:
                    merged["account"]["email_address"] = env_user

                env_pwd = os.getenv("GMAIL_APP_PASSWORD") or os.getenv("GMAIL_PASSWORD")
                if env_pwd:
                    merged["account"]["app_password"] = env_pwd

                env_gemini = os.getenv("GEMINI_API_KEY")
                if env_gemini:
                    merged["ai"]["gemini_api_key"] = env_gemini

            return merged
    except Exception as e:
        print(f"Error reading config for user '{user_id}': {e}. Using defaults.")
        return DEFAULT_CONFIG.copy()


def save_config(new_config: Dict[str, Any], user_id: str = "default") -> bool:
    """Save configuration to disk with encrypted secrets for a specific tenant."""
    get_data_dir().mkdir(parents=True, exist_ok=True)
    config_path = get_tenant_config_path(user_id)
    try:
        to_save = json.loads(json.dumps(new_config))  # deep copy
        
        # Encrypt app password
        if "account" in to_save:
            pwd = to_save["account"].get("app_password", "")
            if pwd and not pwd.startswith("ENC::"):
                to_save["account"]["app_password"] = vault.encrypt(pwd)

        # Encrypt Gemini API key
        if "ai" in to_save:
            key = to_save["ai"].get("gemini_api_key", "")
            if key and not key.startswith("ENC::"):
                to_save["ai"]["gemini_api_key"] = vault.encrypt(key)

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(to_save, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving config for user '{user_id}': {e}")
        return False
