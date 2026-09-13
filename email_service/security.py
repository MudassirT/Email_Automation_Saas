"""
Security Subsystem for Email Automation Service.
Provides:
1. Secret encryption & decryption (Fernet AES)
2. Prompt injection defense and input sanitization
3. Sensitive data leakage prevention for outbound drafts
4. Dispatch guardrails and sliding-window rate limiters
5. Recipient domain & email validation
"""

import os
import re
import time
import base64
from pathlib import Path
from typing import Tuple, Dict, List, Optional
from cryptography.fernet import Fernet

DATA_DIR = Path(__file__).parent / "data"
KEY_FILE = DATA_DIR / ".vault_key"


class SecretVault:
    """Manages encryption and decryption of credentials on disk."""
    
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)

    def _get_or_create_key(self) -> bytes:
        if KEY_FILE.exists():
            try:
                with open(KEY_FILE, "rb") as f:
                    key = f.read().strip()
                if len(key) == 44:  # Standard Fernet key length
                    return key
            except Exception:
                pass
        
        # Generate new key
        new_key = Fernet.generate_key()
        try:
            with open(KEY_FILE, "wb") as f:
                f.write(new_key)
            # On Windows/Unix, restrict file permissions if possible
            os.chmod(KEY_FILE, 0o600)
        except Exception:
            pass
        return new_key

    def encrypt(self, plain_text: str) -> str:
        if not plain_text:
            return ""
        try:
            # Prefix with ENC:: to denote encrypted value
            encrypted = self.cipher.encrypt(plain_text.encode("utf-8")).decode("utf-8")
            return f"ENC::{encrypted}"
        except Exception:
            return plain_text

    def decrypt(self, encrypted_text: str) -> str:
        if not encrypted_text:
            return ""
        if not encrypted_text.startswith("ENC::"):
            # Plaintext fallback (e.g. before migration)
            return encrypted_text
        try:
            token = encrypted_text[5:]
            decrypted = self.cipher.decrypt(token.encode("utf-8")).decode("utf-8")
            return decrypted
        except Exception:
            return ""

    @staticmethod
    def mask(secret: str, show_prefix: int = 4, show_suffix: int = 2) -> str:
        if not secret:
            return ""
        if len(secret) <= (show_prefix + show_suffix):
            return "••••••••"
        return f"{secret[:show_prefix]}••••••••{secret[-show_suffix:]}"


class PromptShield:
    """Defends against prompt injection and adversarial manipulation in incoming emails."""
    
    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"(?i)disregard\s+(all\s+)?(previous|prior|system)\s+rules?",
        r"(?i)you\s+are\s+now\s+(in\s+)?(developer\s+mode|dan\s+mode|unrestricted)",
        r"(?i)print\s+(the\s+)?system\s+prompts?",
        r"(?i)reveal\s+(your\s+)?instructions?",
        r"(?i)send\s+(all\s+)?(passwords?|credentials?|api[_\s]*keys?)",
        r"(?i)system\s*:\s*override",
        r"(?i)jailbreak",
        r"(?i)output\s+(the\s+)?exact\s+prompt",
        r"(?i)forget\s+everything\s+you\s+know",
        r"(?i)new\s+rule:\s*you\s+must"
    ]

    @classmethod
    def detect_injection(cls, text: str) -> Tuple[bool, Optional[str]]:
        """Check if incoming text contains known prompt injection attempts."""
        if not text:
            return False, None
        for pattern in cls.INJECTION_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return True, match.group(0)
        return False, None

    @classmethod
    def sanitize_for_llm(cls, text: str, max_chars: int = 4000) -> str:
        """Sanitize text to prevent delimiter breakage and prompt confusion."""
        if not text:
            return ""
        # Strip null bytes and non-printable control characters (except newline/tab)
        cleaned = "".join(ch for ch in text if ch in ("\n", "\r", "\t") or (32 <= ord(ch) <= 126 or ord(ch) > 127))
        # Disarm custom XML tags that might mimic prompt delimiters
        cleaned = re.sub(r"<\s*/?\s*(system|instruction|untrusted_content|developer_instruction)\s*>", "[tag_sanitized]", cleaned, flags=re.IGNORECASE)
        # Cap length to prevent denial-of-service or token exhaustion
        if len(cleaned) > max_chars:
            cleaned = cleaned[:max_chars] + "\n...[Truncated for security]"
        return cleaned


class DataLeakPreventer:
    """Scans outbound AI drafts to prevent accidental leakage of sensitive keys or tokens."""
    
    LEAK_PATTERNS = [
        (r"AIza[0-9A-Za-z\-_]{30,40}", "Google API Key"),
        (r"-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----", "Private Key"),
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Token"),
        (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack Token"),
        (r"sk-[a-zA-Z0-9]{20,48}", "OpenAI Key"),
        (r"[a-z0-9]{4}\s+[a-z0-9]{4}\s+[a-z0-9]{4}\s+[a-z0-9]{4}", "App Password Pattern"),
        (r"(?i)(password|secret|apikey|token)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?", "Exposed Credential Assignment")
    ]

    @classmethod
    def scan_for_leaks(cls, text: str) -> Tuple[bool, Optional[str]]:
        """Returns True and leak description if sensitive information is detected."""
        if not text:
            return False, None
        for pattern, desc in cls.LEAK_PATTERNS:
            if re.search(pattern, text):
                return True, desc
        return False, None

    @classmethod
    def sanitize_outgoing(cls, text: str) -> str:
        """Redacts any leaked credentials in outgoing text."""
        sanitized = text
        for pattern, desc in cls.LEAK_PATTERNS:
            sanitized = re.sub(pattern, f"[REDACTED_{desc.upper().replace(' ', '_')}]", sanitized)
        return sanitized


class DispatchLimiter:
    """Sliding-window dispatch rate limiter to prevent email flooding or runaway loops."""
    
    def __init__(self, max_per_hour: int = 25):
        self.max_per_hour = max_per_hour
        self.dispatches: List[float] = []

    def can_dispatch(self) -> Tuple[bool, str]:
        now = time.time()
        one_hour_ago = now - 3600
        # Clean older entries
        self.dispatches = [t for t in self.dispatches if t > one_hour_ago]
        
        if len(self.dispatches) >= self.max_per_hour:
            remaining_seconds = int(3600 - (now - self.dispatches[0]))
            return False, f"Dispatch rate limit reached ({self.max_per_hour}/hour). Please wait {remaining_seconds // 60}m."
        return True, "OK"

    def record_dispatch(self):
        self.dispatches.append(time.time())


class APIRateLimiter:
    """In-memory rate limiter for sensitive web endpoints."""
    
    def __init__(self):
        self.requests: Dict[str, List[float]] = {}

    def is_allowed(self, client_key: str, max_requests: int = 30, window_seconds: int = 60) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        records = self.requests.setdefault(client_key, [])
        records = [t for t in records if t > cutoff]
        self.requests[client_key] = records

        if len(records) >= max_requests:
            return False
        records.append(now)
        return True


# Suspicious disposable domain blocklist
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "sharklasers.com", "yopmail.com", "trashmail.com", "dispostable.com"
}

def is_valid_email(email_str: str) -> bool:
    """Validate RFC-compliant email address and ensure domain is not a known throwaway."""
    if not email_str or "@" not in email_str:
        return False
    # Extract clean email if formatted like "Name <email@domain.com>"
    match = re.search(r"<([^>]+)>", email_str)
    raw_email = match.group(1).strip() if match else email_str.strip()
    
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, raw_email):
        return False
        
    domain = raw_email.split("@")[-1].lower()
    if domain in DISPOSABLE_DOMAINS:
        return False
    return True


vault = SecretVault()
dispatch_limiter = DispatchLimiter(max_per_hour=30)
api_rate_limiter = APIRateLimiter()
