"""
Google Gemini Multi-Key Pool & Distributed Token Manager for AutoMail AI SaaS.

Key Architectural Capabilities:
1. Multi-Key Discovery: Dynamically discovers all GOOGLE_API_KEY and GOOGLE_API_KEY_*
   from .env and environment variables.
2. Isolated Per-Key Token Ledgers: Every key tracks its own independent token usage:
   - promptTokenCount, candidatesTokenCount, thoughtsTokenCount, and totalTokenCount.
   - Request volumes, latency, and success/failure ratios.
3. Deterministic Tenant-to-Key Quota Allocation:
   - Maps each tenant/organization to a dedicated key slot so tenants do not exhaust
     each other's token budgets.
   - Respects Tenant BYOK (Bring-Your-Own-Key) overrides if configured in tenant settings.
4. Autonomous High-Availability Failover & Cooldown:
   - If a key encounters rate limits (HTTP 429) or transient 503 errors, it enters a
     time-decaying cooldown and automatically fails over to the next healthy key in the pool.
   - Denied/suspended keys (HTTP 403) are quarantined while the pool continues uninterrupted.
5. Live Administrative Telemetry:
   - Real-time visibility into per-key tokens, tenant assignments, and health states.
"""

import os
import re
import time
import json
import hashlib
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv
import requests

logger = logging.getLogger("automail.gemini_pool")

# Ensure .env is loaded
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=_env_path)
else:
    load_dotenv()


class GeminiKeySlot:
    """Represents an isolated Gemini API Key slot with its own token ledger and health state."""

    def __init__(self, slot_id: str, env_var: str, api_key: str):
        self.slot_id = slot_id
        self.env_var = env_var
        self.api_key = api_key
        self.masked_key = self._mask_key(api_key)
        self.status = "active"  # 'active', 'rate_limited', 'denied', 'error'
        self.cooldown_until: float = 0.0
        self.total_requests: int = 0
        self.total_prompt_tokens: int = 0
        self.total_candidates_tokens: int = 0
        self.total_thoughts_tokens: int = 0
        self.total_tokens: int = 0
        self.last_used_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self.last_latency_ms: float = 0.0
        self.assigned_tenants: List[str] = []
        self._lock = threading.Lock()

    @staticmethod
    def _mask_key(key: str) -> str:
        if not key or len(key) < 10:
            return "***"
        return f"{key[:6]}...{key[-4:]}"

    def is_available(self) -> bool:
        """Check if this slot is healthy and not in rate-limit cooldown."""
        if self.status == "denied":
            return False
        if self.status == "rate_limited":
            if time.time() >= self.cooldown_until:
                self.status = "active"
                self.cooldown_until = 0.0
                return True
            return False
        return self.status == "active"

    def record_usage(self, prompt_tokens: int, candidates_tokens: int, thoughts_tokens: int, total_tokens: int, latency_ms: float):
        with self._lock:
            self.total_requests += 1
            self.total_prompt_tokens += prompt_tokens
            self.total_candidates_tokens += candidates_tokens
            self.total_thoughts_tokens += thoughts_tokens
            self.total_tokens += total_tokens
            self.last_latency_ms = round(latency_ms, 2)
            self.last_used_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.status = "active"

    def mark_rate_limited(self, cooldown_seconds: float = 60.0, error_msg: str = "HTTP 429 Too Many Requests"):
        with self._lock:
            self.status = "rate_limited"
            self.cooldown_until = time.time() + cooldown_seconds
            self.last_error = error_msg

    def mark_denied(self, error_msg: str = "HTTP 403 Access Denied"):
        with self._lock:
            self.status = "denied"
            self.last_error = error_msg

    def mark_error(self, error_msg: str):
        with self._lock:
            self.status = "error"
            self.last_error = error_msg

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            remaining_cooldown = max(0.0, round(self.cooldown_until - now, 1)) if self.cooldown_until > now else 0.0
            return {
                "slot_id": self.slot_id,
                "env_var": self.env_var,
                "masked_key": self.masked_key,
                "status": self.status,
                "is_available": self.is_available(),
                "cooldown_remaining_sec": remaining_cooldown,
                "total_requests": self.total_requests,
                "tokens": {
                    "prompt_tokens": self.total_prompt_tokens,
                    "candidates_tokens": self.total_candidates_tokens,
                    "thoughts_tokens": self.total_thoughts_tokens,
                    "total_tokens": self.total_tokens,
                },
                "last_latency_ms": self.last_latency_ms,
                "last_used_at": self.last_used_at,
                "last_error": self.last_error,
                "assigned_tenant_count": len(self.assigned_tenants)
            }


class GeminiTokenManager:
    """Centralized Multi-Key Pool & Token Manager for Google Gemini API."""

    DEFAULT_MODEL = "gemini-3.6-flash"
    FALLBACK_MODELS = ["gemini-2.5-flash", "gemini-flash-latest"]

    def __init__(self):
        self._slots: Dict[str, GeminiKeySlot] = {}
        self._slot_order: List[str] = []
        self._tenant_assignments: Dict[str, str] = {}
        self._lock = threading.RLock()
        self.reload_keys_from_env()

    def reload_keys_from_env(self):
        """Scans environment and .env for all GOOGLE_API_KEY definitions."""
        with self._lock:
            # Re-read .env in case it was updated
            if _env_path.exists():
                load_dotenv(dotenv_path=_env_path, override=True)

            discovered: List[Tuple[str, str, str]] = []  # (slot_id, env_var, key_value)

            # Primary key
            pk = os.getenv("GOOGLE_API_KEY", "").strip()
            if pk:
                discovered.append(("key_slot_1", "GOOGLE_API_KEY", pk))

            # Additional keys GOOGLE_API_KEY_2, GOOGLE_API_KEY_3, etc.
            numbered_keys = []
            for k, v in os.environ.items():
                if k.startswith("GOOGLE_API_KEY_") and v.strip():
                    try:
                        num = int(k.split("_")[-1])
                        numbered_keys.append((num, k, v.strip()))
                    except ValueError:
                        continue

            numbered_keys.sort(key=lambda x: x[0])
            for num, env_name, val in numbered_keys:
                discovered.append((f"key_slot_{num}", env_name, val))

            new_slots = {}
            new_order = []
            for slot_id, env_var, key_val in discovered:
                # Preserve existing metrics if slot already existed
                if slot_id in self._slots and self._slots[slot_id].api_key == key_val:
                    new_slots[slot_id] = self._slots[slot_id]
                else:
                    new_slots[slot_id] = GeminiKeySlot(slot_id, env_var, key_val)
                new_order.append(slot_id)

            self._slots = new_slots
            self._slot_order = new_order
            logger.info(f"GeminiTokenManager initialized with {len(self._slots)} key slots.")

    @property
    def total_slots(self) -> int:
        return len(self._slots)

    def get_all_slots(self) -> List[GeminiKeySlot]:
        with self._lock:
            return [self._slots[sid] for sid in self._slot_order if sid in self._slots]

    def get_slot_for_tenant(self, tenant_id: str = "default") -> Optional[GeminiKeySlot]:
        """
        Determines the assigned Gemini key slot for a given tenant.
        Uses deterministic hashing for quota isolation across tenants.
        """
        with self._lock:
            if not self._slots:
                return None

            clean_tenant = tenant_id or "default"

            # Check cached or assigned mapping
            if clean_tenant in self._tenant_assignments:
                sid = self._tenant_assignments[clean_tenant]
                if sid in self._slots and self._slots[sid].is_available():
                    return self._slots[sid]

            # Available healthy slots
            available = [self._slots[sid] for sid in self._slot_order if self._slots[sid].is_available()]
            if not available:
                # Fallback to any non-denied slot if all are cooling down
                fallback = [self._slots[sid] for sid in self._slot_order if self._slots[sid].status != "denied"]
                if fallback:
                    available = fallback
                else:
                    return None

            # Deterministic hash modulo assignment
            hash_val = int(hashlib.md5(clean_tenant.encode("utf-8")).hexdigest(), 16)
            idx = hash_val % len(available)
            chosen = available[idx]

            # Bind tenant to this slot
            self._tenant_assignments[clean_tenant] = chosen.slot_id
            if clean_tenant not in chosen.assigned_tenants:
                chosen.assigned_tenants.append(clean_tenant)

            return chosen

    def execute_with_failover(
        self,
        tenant_id: str,
        contents: List[Dict[str, Any]],
        generation_config: Optional[Dict[str, Any]] = None,
        model_name: Optional[str] = None,
        byok_key: Optional[str] = None,
        timeout: float = 18.0
    ) -> Dict[str, Any]:
        """
        Executes generateContent with per-key token tracking and automatic high-availability failover.
        """
        model = model_name or self.DEFAULT_MODEL
        if model == "gemini-1.5-flash":
            model = self.DEFAULT_MODEL  # Auto-upgrade deprecated v1.5 to active v3.6/v2.5

        # 1. BYOK (Bring Your Own Key) handling
        if byok_key and byok_key.strip():
            return self._call_gemini_api(
                api_key=byok_key.strip(),
                contents=contents,
                generation_config=generation_config,
                model=model,
                timeout=timeout,
                slot=None
            )

        # 2. Key Pool Execution with Failover
        primary_slot = self.get_slot_for_tenant(tenant_id)
        if not primary_slot:
            raise RuntimeError("No available Gemini API keys in the key pool.")

        # Candidate order: primary slot first, followed by remaining available slots
        candidate_slots = [primary_slot] + [
            s for s in self.get_all_slots() if s.slot_id != primary_slot.slot_id and s.is_available()
        ]

        last_error = None
        for slot in candidate_slots:
            if not slot.is_available() and len(candidate_slots) > 1:
                continue

            try:
                result = self._call_gemini_api(
                    api_key=slot.api_key,
                    contents=contents,
                    generation_config=generation_config,
                    model=model,
                    timeout=timeout,
                    slot=slot
                )
                result["slot_id"] = slot.slot_id
                result["masked_key"] = slot.masked_key
                return result

            except requests.HTTPError as he:
                status_code = he.response.status_code if he.response is not None else 500
                err_text = he.response.text[:200] if he.response is not None else str(he)
                last_error = f"HTTP {status_code}: {err_text}"

                if status_code == 429:
                    slot.mark_rate_limited(cooldown_seconds=60.0, error_msg=f"HTTP 429 Rate Limit: {err_text}")
                    logger.warning(f"Slot {slot.slot_id} hit rate limit (429). Failing over to next key...")
                elif status_code == 403:
                    slot.mark_denied(error_msg=f"HTTP 403 Denied: {err_text}")
                    logger.warning(f"Slot {slot.slot_id} access denied (403). Quarantined. Failing over...")
                elif status_code == 404:
                    # Model not supported on this key; try fallback model on same key
                    for fb_model in self.FALLBACK_MODELS:
                        try:
                            res = self._call_gemini_api(slot.api_key, contents, generation_config, fb_model, timeout, slot)
                            res["slot_id"] = slot.slot_id
                            res["masked_key"] = slot.masked_key
                            return res
                        except Exception:
                            continue
                    slot.mark_error(f"HTTP 404 Model {model} Not Found")
                else:
                    slot.mark_error(last_error)

            except Exception as ex:
                last_error = str(ex)
                slot.mark_error(last_error)
                logger.warning(f"Slot {slot.slot_id} failed with error: {ex}. Failing over...")

        raise RuntimeError(f"All Gemini key pool slots failed. Last error: {last_error}")

    def _call_gemini_api(
        self,
        api_key: str,
        contents: List[Dict[str, Any]],
        generation_config: Optional[Dict[str, Any]],
        model: str,
        timeout: float,
        slot: Optional[GeminiKeySlot] = None
    ) -> Dict[str, Any]:
        """Direct REST invocation to Google Gemini API with token usage parsing."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload: Dict[str, Any] = {"contents": contents}
        if generation_config:
            payload["generationConfig"] = generation_config

        start_time = time.perf_counter()
        resp = requests.post(url, json=payload, timeout=timeout)
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        resp.raise_for_status()
        data = resp.json()

        # Extract generated text
        candidates = data.get("candidates", [])
        if not candidates or "content" not in candidates[0]:
            raise ValueError("Empty or invalid candidate response from Gemini API.")

        parts = candidates[0]["content"].get("parts", [])
        raw_text = "".join(p.get("text", "") for p in parts)

        # Parse usageMetadata (exact tokens provided by Google Gemini)
        usage = data.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount", 0)
        cand_tokens = usage.get("candidatesTokenCount", 0)
        thought_tokens = usage.get("thoughtsTokenCount", 0)
        total_tokens = usage.get("totalTokenCount", prompt_tokens + cand_tokens + thought_tokens)

        # Update slot token ledger
        if slot:
            slot.record_usage(
                prompt_tokens=prompt_tokens,
                candidates_tokens=cand_tokens,
                thoughts_tokens=thought_tokens,
                total_tokens=total_tokens,
                latency_ms=latency_ms
            )

        return {
            "text": raw_text,
            "prompt_tokens": prompt_tokens,
            "candidates_tokens": cand_tokens,
            "thoughts_tokens": thought_tokens,
            "total_tokens": total_tokens,
            "latency_ms": round(latency_ms, 2),
            "model": model,
            "finish_reason": candidates[0].get("finishReason", "STOP")
        }

    def get_telemetry(self) -> Dict[str, Any]:
        """Provides holistic visibility into all keys, tokens, and health states."""
        with self._lock:
            slots_data = [s.to_dict() for s in self.get_all_slots()]
            active_count = sum(1 for s in slots_data if s["status"] == "active")
            rate_limited_count = sum(1 for s in slots_data if s["status"] == "rate_limited")
            denied_count = sum(1 for s in slots_data if s["status"] == "denied")

            total_tokens = sum(s["tokens"]["total_tokens"] for s in slots_data)
            total_requests = sum(s["total_requests"] for s in slots_data)

            return {
                "total_keys_configured": len(slots_data),
                "active_healthy_keys": active_count,
                "rate_limited_keys": rate_limited_count,
                "denied_keys": denied_count,
                "aggregate_total_tokens": total_tokens,
                "aggregate_total_requests": total_requests,
                "default_model": self.DEFAULT_MODEL,
                "slots": slots_data
            }


# Singleton Key Pool Manager
gemini_token_manager = GeminiTokenManager()
