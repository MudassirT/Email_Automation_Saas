"""
Authentication Subsystem for Email Automation SaaS.
Provides:
1. User registration & authentication with PBKDF2-HMAC-SHA256 password hashing.
2. Signed JWT session tokens with 30-day persistence.
3. Google OAuth 2.0 Client with .env credential loading and demo fallback.
4. Automatic provisioning and binding to isolated tenant partitions.
5. Role-Based Access Control (Admin vs Standard User).
"""

import os
import re
import json
import time
import base64
import hashlib
import secrets
import hmac
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import threading

import jwt
from dotenv import load_dotenv

# Load environment variables from .env file
BASE_DIR = Path(__file__).parent.parent
ENV_FILE = BASE_DIR / ".env"
if ENV_FILE.exists():
    load_dotenv(dotenv_path=str(ENV_FILE))
else:
    load_dotenv()

DATA_DIR = Path(__file__).parent / "data"
USERS_FILE = DATA_DIR / "users.json"
_user_lock = threading.Lock()

# Environment & Configuration Secrets
APP_ENV = os.getenv("ENVIRONMENT") or os.getenv("APP_ENV") or os.getenv("ENV") or "development"
APP_ENV = APP_ENV.strip().lower()

_raw_jwt_key = os.getenv("JWT_SECRET_KEY", "").strip()

INSECURE_DEFAULT_KEYS = {
    "",
    "automail_secure_jwt_secret_key_default_2026",
    "your_jwt_secret_key_here",
    "change_this_in_production",
    "automail_secure_jwt_secret_key_8f93e4b7c12d56a0",
    "secret",
    "default"
}

def validate_jwt_secret():
    """
    Enforces that non-dev environments fail immediately on unset or default JWT_SECRET_KEY.
    Prevents silent fallback vulnerabilities in production.
    """
    if APP_ENV not in ("development", "dev", "test", "testing", "local"):
        if not _raw_jwt_key or _raw_jwt_key in INSECURE_DEFAULT_KEYS or len(_raw_jwt_key) < 32:
            raise RuntimeError(
                f"FATAL SECURITY VIOLATION: In environment '{APP_ENV}', JWT_SECRET_KEY must be "
                f"an explicitly configured, cryptographically strong secret (minimum 32 characters). "
                f"Silent fallback is prohibited. Server startup aborted."
            )

# Execute hard validation check at startup
validate_jwt_secret()

JWT_SECRET_KEY = _raw_jwt_key if _raw_jwt_key else "automail_secure_jwt_secret_key_default_2026"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 30 * 24 * 3600  # 30 days

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_CALLBACK_URL = os.getenv("GOOGLE_CALLBACK_URL", "http://localhost:8000/api/auth/google/callback").strip()


def hash_password(plain_password: str) -> str:
    """Hash password with PBKDF2-HMAC-SHA256 and a cryptographically random salt."""
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100000)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    return f"{salt_b64}${key_b64}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify plain password against stored salt$hash."""
    if not password_hash or "$" not in password_hash:
        return False
    try:
        salt_b64, key_b64 = password_hash.split("$", 1)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected_key = base64.b64decode(key_b64.encode("ascii"))
        test_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(test_key, expected_key)
    except Exception:
        return False


def create_jwt_token(user_or_id: Any, email: str = "", role: str = "user", name: str = "") -> str:
    """Issue a signed JWT session token from user dict or positional parameters."""
    if isinstance(user_or_id, dict):
        user_id = user_or_id.get("id") or user_or_id.get("sub", "default")
        email = user_or_id.get("email", "")
        role = user_or_id.get("role", "user")
        name = user_or_id.get("name", "")
    else:
        user_id = str(user_or_id)

    now = int(time.time())
    payload = {
        "sub": user_id,
        "email": email,
        "name": name or email,
        "role": role,
        "iat": now,
        "exp": now + JWT_EXPIRATION_SECONDS
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT session token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception:
        return None


class UserManager:
    """Manages user persistence, registration, credentials, and tenant binding."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.users: Dict[str, Dict[str, Any]] = {}
        self._load_or_init()

    def _load_or_init(self):
        with _user_lock:
            if USERS_FILE.exists():
                try:
                    with open(USERS_FILE, "r", encoding="utf-8") as f:
                        self.users = json.load(f)
                except Exception:
                    self.users = {}

            # Seed default admin user if not present
            if "default" not in self.users:
                admin_user = {
                    "user_id": "default",
                    "email": "admin@automail.ai",
                    "name": "System Administrator",
                    "password_hash": hash_password("admin123"),
                    "role": "admin",
                    "auth_provider": "local",
                    "picture": "",
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "last_login": time.strftime("%Y-%m-%dT%H:%M:%S")
                }
                self.users["default"] = admin_user
                self._save_unlocked()

    def _save_unlocked(self):
        try:
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            print(f"Error saving users.json: {e}")

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with _user_lock:
            u = self.users.get(user_id)
            if u:
                return self._safe_user_copy(u)
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        clean_email = email.strip().lower()
        with _user_lock:
            for u in self.users.values():
                if u.get("email", "").lower() == clean_email:
                    return self._safe_user_copy(u)
            return None

    def _safe_user_copy(self, u: Dict[str, Any]) -> Dict[str, Any]:
        """Strip password hash for security before passing to outer layers."""
        copy = dict(u)
        copy.pop("password_hash", None)
        uid = copy.get("user_id") or copy.get("id", "")
        copy["id"] = uid
        copy["user_id"] = uid
        return copy

    def register_user(
        self,
        email: str,
        password: str,
        name: str = "",
        role: str = "user",
        display_name: str = ""
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Register a new user account with unique email and isolated tenant workspace."""
        clean_email = email.strip().lower()
        effective_name = (name or display_name).strip() or clean_email.split("@")[0].capitalize()
        if not clean_email or "@" not in clean_email:
            return False, "Invalid email address format.", None

        if len(password) < 6:
            return False, "Password must be at least 6 characters.", None

        with _user_lock:
            for u in self.users.values():
                if u.get("email", "").lower() == clean_email:
                    return False, "An account with this email already exists.", None

            # Generate unique safe tenant user ID
            username_prefix = re.sub(r"[^a-zA-Z0-9_]", "", clean_email.split("@")[0])[:12]
            random_suffix = secrets.token_hex(4)
            user_id = f"usr_{username_prefix}_{random_suffix}".lower()

            new_user = {
                "user_id": user_id,
                "email": clean_email,
                "name": effective_name,
                "password_hash": hash_password(password),
                "role": role,
                "auth_provider": "local",
                "picture": "",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "last_login": time.strftime("%Y-%m-%dT%H:%M:%S")
            }

            self.users[user_id] = new_user
            self._save_unlocked()

        # Provision isolated tenant storage & default config
        from .storage import storage
        from .config import save_config
        storage.for_user(user_id)
        save_config({
            "account": {"email_address": clean_email, "imap_server": "imap.gmail.com"},
            "ai": {"provider": "gemini"},
            "automation": {"mode": "review_required"}
        }, user_id=user_id)
        storage.for_user(user_id).log("AUTH", f"Account registered for '{clean_email}' with isolated tenant workspace.", "SUCCESS")

        return True, "Registration successful!", self._safe_user_copy(new_user)

    def authenticate_local(self, email: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Authenticate user with email and password."""
        clean_email = email.strip().lower()
        with _user_lock:
            target = None
            for u in self.users.values():
                if u.get("email", "").lower() == clean_email:
                    target = u
                    break

            if not target:
                return False, "Invalid email or password.", None

            if not verify_password(password, target.get("password_hash", "")):
                return False, "Invalid email or password.", None

            target["last_login"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            self._save_unlocked()
            return True, "Login successful!", self._safe_user_copy(target)

    def find_or_create_google_user(
        self,
        email_or_info: Any,
        name: str = "",
        google_id: str = "",
        picture: str = ""
    ) -> Dict[str, Any]:
        """Find existing user by email or provision new isolated Google user account."""
        if isinstance(email_or_info, dict):
            email = email_or_info.get("email", "")
            name = email_or_info.get("name") or name
            google_id = email_or_info.get("google_id") or email_or_info.get("sub") or google_id
            picture = email_or_info.get("picture") or picture
        else:
            email = str(email_or_info)

        clean_email = email.strip().lower()

        with _user_lock:
            for u in self.users.values():
                if u.get("email", "").lower() == clean_email or (google_id and u.get("google_id") == google_id):
                    # Update profile info
                    if google_id:
                        u["google_id"] = google_id
                    if picture:
                        u["picture"] = picture
                    if name:
                        u["name"] = name
                    u["last_login"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    self._save_unlocked()
                    return self._safe_user_copy(u)

            # Create new user for Google Sign-In
            username_prefix = re.sub(r"[^a-zA-Z0-9_]", "", clean_email.split("@")[0])[:12]
            random_suffix = secrets.token_hex(4)
            user_id = f"goog_{username_prefix}_{random_suffix}".lower()

            new_user = {
                "user_id": user_id,
                "email": clean_email,
                "name": name or clean_email.split("@")[0].capitalize(),
                "password_hash": hash_password(secrets.token_hex(16)),  # Random password
                "role": "user",
                "auth_provider": "google",
                "google_id": google_id,
                "picture": picture,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "last_login": time.strftime("%Y-%m-%dT%H:%M:%S")
            }

            self.users[user_id] = new_user
            self._save_unlocked()

        # Provision isolated tenant workspace
        from .storage import storage
        from .config import save_config
        storage.for_user(user_id)
        save_config({
            "account": {"email_address": clean_email, "imap_server": "imap.gmail.com"},
            "ai": {"provider": "gemini"},
            "automation": {"mode": "review_required"}
        }, user_id=user_id)
        storage.for_user(user_id).log("AUTH", f"Google Sign-In account created for '{clean_email}'.", "SUCCESS")

        return self._safe_user_copy(new_user)


class GoogleOAuthClient:
    """Manages Google OAuth 2.0 URL generation, token exchange, and .env configuration."""

    @property
    def client_id(self) -> str:
        return os.getenv("GOOGLE_CLIENT_ID", "").strip()

    @property
    def redirect_uri(self) -> str:
        return os.getenv("GOOGLE_CALLBACK_URL", "http://localhost:8000/api/auth/google/callback").strip()

    @classmethod
    def is_configured(cls) -> bool:
        client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
        return bool(client_id and client_secret and "your_google_client_id" not in client_id)

    @classmethod
    def get_auth_url(cls, state: Optional[str] = None) -> Dict[str, Any]:
        client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
        callback_url = os.getenv("GOOGLE_CALLBACK_URL", "http://localhost:8000/api/auth/google/callback").strip()

        if not cls.is_configured():
            return {
                "configured": False,
                "message": "Google OAuth is awaiting your GOOGLE_CLIENT_ID in .env. You can also use Instant Google Demo login.",
                "demo_login_available": True,
                "callback_url": callback_url
            }

        state_token = state or secrets.token_urlsafe(16)
        params = {
            "client_id": client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "state": state_token,
            "prompt": "consent"
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"https://accounts.google.com/o/oauth2/v2/auth?{query}"
        return {
            "configured": True,
            "auth_url": url,
            "callback_url": callback_url,
            "state": state_token
        }

    @classmethod
    def get_authorization_url(cls, state: Optional[str] = None) -> str:
        """Returns the full Google OAuth redirection URL."""
        res = cls.get_auth_url(state)
        if res.get("configured") and res.get("auth_url"):
            return res["auth_url"]
        cid = os.getenv("GOOGLE_CLIENT_ID", "your_google_client_id")
        cb = os.getenv("GOOGLE_CALLBACK_URL", "http://localhost:8000/api/auth/google/callback")
        return f"https://accounts.google.com/o/oauth2/v2/auth?client_id={cid}&redirect_uri={cb}&response_type=code&scope=openid%20email%20profile"

    @classmethod
    def exchange_code_for_token(cls, code: str) -> Optional[Dict[str, Any]]:
        success, msg, user = cls.exchange_code_for_user(code)
        if success and user:
            return user
        return None

    @classmethod
    def exchange_code_for_user(cls, code: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Exchange Google authorization code for token and user profile."""
        import requests

        client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
        callback_url = os.getenv("GOOGLE_CALLBACK_URL", "http://localhost:8000/api/auth/google/callback").strip()

        if not client_id or not client_secret:
            return False, "Google OAuth credentials not configured in .env", None

        # 1. Exchange code for access token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": callback_url,
            "grant_type": "authorization_code"
        }
        try:
            resp = requests.post(token_url, data=data, timeout=10)
            token_json = resp.json()
            if "error" in token_json:
                return False, f"Google token exchange failed: {token_json.get('error_description', token_json.get('error'))}", None

            access_token = token_json.get("access_token")
            if not access_token:
                return False, "Failed to obtain access token from Google", None

            # 2. Fetch User Profile
            userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
            user_resp = requests.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
            user_info = user_resp.json()

            email = user_info.get("email")
            name = user_info.get("name") or user_info.get("given_name", "Google User")
            google_id = user_info.get("sub", "")
            picture = user_info.get("picture", "")

            if not email:
                return False, "Google profile did not provide an email address", None

            user = user_manager.find_or_create_google_user(
                email=email,
                name=name,
                google_id=google_id,
                picture=picture
            )
            return True, "Authenticated via Google", user

        except Exception as e:
            return False, f"Google OAuth communication error: {str(e)}", None


user_manager = UserManager()
google_oauth = GoogleOAuthClient()
