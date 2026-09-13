"""
Redis client and distributed caching / rate-limiting manager for AutoMail AI SaaS.
Supports:
1. Distributed sliding-window rate limiting across horizontally-scaled replicas.
2. Fast token revocation / JWT blacklist.
3. High-speed cache for tenant stats and briefings.
Gracefully falls back to local memory if REDIS_URL is unreachable in local dev.
"""

import os
import time
from typing import Optional, Tuple, Dict, List
import redis.asyncio as aioredis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis_pool: Optional[aioredis.Redis] = None
_redis_healthy = False


async def get_redis() -> Optional[aioredis.Redis]:
    """Retrieve async Redis connection pool or None if unavailable."""
    global _redis_pool, _redis_healthy
    if _redis_pool is None:
        try:
            _redis_pool = aioredis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=1.0,
                socket_timeout=1.0
            )
            await _redis_pool.ping()
            _redis_healthy = True
        except Exception:
            _redis_healthy = False
            return None
    return _redis_pool if _redis_healthy else None


class DistributedRateLimiter:
    """
    Sliding-window distributed rate limiter backed by Redis.
    Falls back gracefully to local memory when Redis is disconnected.
    """
    def __init__(self):
        self._fallback_records: Dict[str, List[float]] = {}

    async def is_allowed(
        self,
        client_key: str,
        max_requests: int = 30,
        window_seconds: int = 60
    ) -> Tuple[bool, int]:
        """
        Check if request is allowed within sliding window.
        Returns (is_allowed, remaining_requests).
        """
        now = time.time()
        client = await get_redis()

        if client:
            try:
                redis_key = f"rate_limit:{client_key}"
                pipe = client.pipeline()
                pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
                pipe.zadd(redis_key, {str(now): now})
                pipe.zcard(redis_key)
                pipe.expire(redis_key, window_seconds + 5)
                _, _, current_count, _ = await pipe.execute()

                allowed = current_count <= max_requests
                remaining = max(0, max_requests - current_count)
                return allowed, remaining
            except Exception:
                pass  # Fall back to in-memory

        # In-memory fallback
        cutoff = now - window_seconds
        records = self._fallback_records.setdefault(client_key, [])
        records = [t for t in records if t > cutoff]
        records.append(now)
        self._fallback_records[client_key] = records

        allowed = len(records) <= max_requests
        remaining = max(0, max_requests - len(records))
        return allowed, remaining


class TokenBlacklist:
    """Distributed JWT revocation registry."""
    def __init__(self):
        self._local_blacklist = set()

    async def revoke_token(self, jti_or_token: str, ttl_seconds: int = 86400):
        client = await get_redis()
        if client:
            try:
                await client.setex(f"blacklist:{jti_or_token}", ttl_seconds, "revoked")
                return
            except Exception:
                pass
        self._local_blacklist.add(jti_or_token)

    async def is_revoked(self, jti_or_token: str) -> bool:
        client = await get_redis()
        if client:
            try:
                val = await client.get(f"blacklist:{jti_or_token}")
                return val is not None
            except Exception:
                pass
        return jti_or_token in self._local_blacklist


rate_limiter = DistributedRateLimiter()
token_blacklist = TokenBlacklist()
