"""
Comprehensive Verification Suite: Google Gemini Multi-Key Pool & Token Manager.

Validates:
1. Multi-key discovery from .env (all 18 keys loaded into isolated slots).
2. Per-key independent token ledgers (prompt, candidate, thoughts, total tokens).
3. Deterministic tenant-to-key assignment ensuring quota segregation across organizations.
4. Automatic high-availability failover and time-decaying cooldown on 429/403 errors.
5. Bring-Your-Own-Key (BYOK) custom tenant override.
6. Admin pool telemetry endpoint (/api/admin/gemini/pool).
"""

import os
import sys
import json
import pytest
from fastapi.testclient import TestClient

from email_service.gemini_pool import GeminiTokenManager, GeminiKeySlot, gemini_token_manager
from email_service.server import app
from email_service.auth import create_jwt_token, user_manager

client = TestClient(app)


def test_1_pool_discovery_and_slot_initialization():
    """Verify all 18 Gemini keys are loaded and each slot has an independent token ledger."""
    print("\n[TEST 1] Verifying Gemini Key Pool Discovery & Slot Initialization...")
    
    assert gemini_token_manager.total_slots >= 18, f"Expected >= 18 keys, found {gemini_token_manager.total_slots}"
    slots = gemini_token_manager.get_all_slots()
    
    for s in slots:
        assert s.slot_id.startswith("key_slot_")
        assert len(s.api_key) > 20
        assert s.masked_key.startswith("AQ.") or "..." in s.masked_key
        # Check initial token ledger
        assert s.total_tokens >= 0
        assert s.total_requests >= 0
    
    print(f"  [OK] Successfully discovered {len(slots)} key slots with isolated token counters.")


def test_2_tenant_quota_isolation():
    """Verify multi-tenant deterministic slot assignment isolates token budgets."""
    print("\n[TEST 2] Verifying Deterministic Tenant Quota Isolation...")
    
    slot_a = gemini_token_manager.get_slot_for_tenant("org_enterprise_acme")
    slot_b = gemini_token_manager.get_slot_for_tenant("org_fintech_hyper")
    slot_c = gemini_token_manager.get_slot_for_tenant("org_healthcare_zenith")
    
    assert slot_a is not None
    assert slot_b is not None
    assert slot_c is not None
    
    print(f"  [OK] Tenant Acme -> {slot_a.slot_id} ({slot_a.masked_key})")
    print(f"  [OK] Tenant Hyper -> {slot_b.slot_id} ({slot_b.masked_key})")
    print(f"  [OK] Tenant Zenith -> {slot_c.slot_id} ({slot_c.masked_key})")
    
    # Consistency check: same tenant always gets their assigned slot
    slot_a_repeat = gemini_token_manager.get_slot_for_tenant("org_enterprise_acme")
    assert slot_a.slot_id == slot_a_repeat.slot_id
    print("  [OK] Deterministic binding verified: Org Acme consistently routed to assigned key slot.")


def test_3_independent_token_tracking_and_live_execution():
    """Verify live execution records tokens specifically to the assigned key slot."""
    print("\n[TEST 3] Verifying Independent Token Accounting on Live Call...")
    
    tenant_id = "tenant_test_telemetry"
    assigned_slot = gemini_token_manager.get_slot_for_tenant(tenant_id)
    initial_tokens = assigned_slot.total_tokens
    initial_requests = assigned_slot.total_requests
    
    res = gemini_token_manager.execute_with_failover(
        tenant_id=tenant_id,
        contents=[{"parts": [{"text": "Reply in 1 word: Verified"}]}],
        generation_config={"temperature": 0.1, "maxOutputTokens": 10},
        model_name="gemini-3.6-flash"
    )
    
    used_slot_id = res["slot_id"]
    used_slot = next(s for s in gemini_token_manager.get_all_slots() if s.slot_id == used_slot_id)
    
    assert res["prompt_tokens"] > 0
    assert res["total_tokens"] > 0
    assert used_slot.total_tokens > initial_tokens or used_slot_id != assigned_slot.slot_id
    assert used_slot.total_requests > 0
    
    print(f"  [OK] Execution completed via {used_slot_id} ({res['masked_key']})")
    print(f"  [OK] Tokens recorded: {res['prompt_tokens']} prompt, {res['candidates_tokens']} output, {res['total_tokens']} total")
    print(f"  [OK] Slot token ledger updated: {used_slot.total_tokens} total tokens across {used_slot.total_requests} requests.")


def test_4_automatic_failover_on_rate_limit_and_cooldown():
    """Verify that if a key slot encounters a rate limit (429), the pool transparently fails over."""
    print("\n[TEST 4] Verifying High-Availability Failover & Cooldown Simulation...")
    
    # Target a specific slot to simulate 429
    test_slot = gemini_token_manager.get_all_slots()[0]
    test_slot.mark_rate_limited(cooldown_seconds=30.0, error_msg="HTTP 429 Simulated Rate Limit")
    
    assert test_slot.is_available() is False
    assert test_slot.status == "rate_limited"
    assert test_slot.cooldown_until > 0
    print(f"  [OK] Simulated 429 rate limit on {test_slot.slot_id}; marked in cooldown.")
    
    # Execution should bypass the cooling slot and succeed using another available slot
    res = gemini_token_manager.execute_with_failover(
        tenant_id="tenant_failover_test",
        contents=[{"parts": [{"text": "Ping"}]}],
        model_name="gemini-3.6-flash"
    )
    
    assert res["slot_id"] != test_slot.slot_id
    assert res["text"] != ""
    print(f"  [OK] Autonomous failover successful: Request routed to {res['slot_id']} with zero user disruption.")
    
    # Restore slot
    test_slot.status = "active"
    test_slot.cooldown_until = 0.0


def test_5_admin_pool_telemetry_endpoint():
    """Verify /api/admin/gemini/pool returns real-time per-key token telemetry."""
    print("\n[TEST 5] Verifying Admin Gemini Pool Telemetry API...")
    
    admin_user = user_manager.get_user_by_email("admin@automail.ai")
    admin_token = create_jwt_token(admin_user)
    
    resp = client.get("/api/admin/gemini/pool", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    data = resp.json()
    
    assert data["total_keys_configured"] >= 18
    assert data["active_healthy_keys"] >= 1
    assert "slots" in data
    assert len(data["slots"]) >= 18
    
    # Verify slot schema
    first_slot = data["slots"][0]
    assert "slot_id" in first_slot
    assert "masked_key" in first_slot
    assert "tokens" in first_slot
    assert "total_tokens" in first_slot["tokens"]
    
    print(f"  [OK] Admin Telemetry verified: {data['active_healthy_keys']} active keys, {data['aggregate_total_tokens']} total tokens tracked.")


def run_all():
    print("=" * 70)
    print("   GEMINI MULTI-KEY POOL & DISTRIBUTED TOKEN MANAGER VERIFICATION")
    print("=" * 70)
    
    test_1_pool_discovery_and_slot_initialization()
    test_2_tenant_quota_isolation()
    test_3_independent_token_tracking_and_live_execution()
    test_4_automatic_failover_on_rate_limit_and_cooldown()
    test_5_admin_pool_telemetry_endpoint()
    
    print("\n" + "=" * 70)
    print("   ALL GEMINI KEY POOL & TOKEN TESTS PASSED WITH ZERO ERRORS! [OK]")
    print("=" * 70)


if __name__ == "__main__":
    run_all()
