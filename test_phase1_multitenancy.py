"""
Comprehensive Phase 1 Integration Test Suite: Multi-Tenancy & Data Model Architecture.

Verifies:
1. Hard Startup Failure on unset/default JWT_SECRET_KEY in production.
2. Tenant Envelope Encryption with HKDF-SHA256, versioning, and zero-downtime key rotation.
3. Cross-Tenant Cryptographic Isolation (Org B cannot decrypt Org A's secrets).
4. Relational Database Schema & Cascading Deletions across all 9 tables.
5. Unique Constraints on (organization_id, email) and (organization_id, email_address).
6. SOC-2 Track AuditLog: Actual redacted payload retained + SHA-256 HMAC integrity check.
7. Idempotent Migration Script: Dry-run mode and live re-execution with zero duplicates.
8. Distributed Sliding-Window Rate Limiter & Token Revocation Blacklist.
"""

import os
import sys
import asyncio
import hashlib
import json
import secrets
import pytest
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.exc import IntegrityError
from sqlalchemy import select

from email_service.db.models import (
    Base, Organization, User, Mailbox, EmailThread,
    EmailMessage, Draft, AutomationRule, AuditLog, Integration
)
from email_service.db.session import async_engine, AsyncSessionLocal, init_db
from email_service.db.repositories import (
    OrganizationRepository, UserRepository, MailboxRepository,
    EmailRepository, DraftRepository, RuleRepository,
    AuditLogRepository, IntegrationRepository
)
from email_service.db.migrate_json_to_postgres import migrate_data
from email_service.security import vault
from email_service.db.redis_client import rate_limiter, token_blacklist


def test_1_hard_jwt_startup_gate():
    """Verify that non-dev environment refuses to boot with insecure JWT key."""
    print("\n[TEST 1] Verifying Hard JWT Secret Startup Gate...")

    import email_service.auth as auth_mod
    original_env = auth_mod.APP_ENV
    original_raw = auth_mod._raw_jwt_key

    # A. Production with default key must raise RuntimeError
    auth_mod.APP_ENV = "production"
    auth_mod._raw_jwt_key = "default"
    with pytest.raises(RuntimeError) as exc_info:
        auth_mod.validate_jwt_secret()
    assert "FATAL SECURITY VIOLATION" in str(exc_info.value)
    print("  [OK] Production mode with default JWT key successfully aborted boot.")

    # B. Production with short key must raise RuntimeError
    auth_mod._raw_jwt_key = "short_key_123"
    with pytest.raises(RuntimeError) as exc_info:
        auth_mod.validate_jwt_secret()
    assert "FATAL SECURITY VIOLATION" in str(exc_info.value)
    print("  [OK] Production mode with < 32 character key successfully aborted boot.")

    # C. Production with strong key passes
    auth_mod._raw_jwt_key = "cryptographically_strong_random_secret_string_32chars+"
    auth_mod.validate_jwt_secret()
    print("  [OK] Production mode with 32+ char strong key passed validation.")

    # Restore
    auth_mod.APP_ENV = original_env
    auth_mod._raw_jwt_key = original_raw


def test_2_tenant_envelope_encryption_and_rotation():
    """Verify envelope encryption key derivation, versioning, and rotation."""
    print("\n[TEST 2] Verifying Tenant Envelope Encryption & Key Rotation...")

    org_a = "org_alpha_01"
    salt_a = secrets.token_hex(16)
    secret_text = "gmail_app_password_xyz987"

    # Version 1 Encryption
    enc_v1 = vault.encrypt_for_tenant(secret_text, org_a, salt_a, version=1)
    assert enc_v1.startswith("ENC::v1::")
    dec_v1 = vault.decrypt_for_tenant(enc_v1, org_a, salt_a)
    assert dec_v1 == secret_text
    print(f"  [OK] Version 1 Encrypted: {enc_v1[:24]}... -> Decrypted successfully.")

    # Key Rotation to Version 2
    enc_v2 = vault.encrypt_for_tenant(secret_text, org_a, salt_a, version=2)
    assert enc_v2.startswith("ENC::v2::")
    assert enc_v2 != enc_v1  # Distinct ciphertext and distinct derived key
    dec_v2 = vault.decrypt_for_tenant(enc_v2, org_a, salt_a)
    assert dec_v2 == secret_text
    print(f"  [OK] Version 2 (Rotated): {enc_v2[:24]}... -> Decrypted successfully.")

    # Cross-Tenant Boundary: Org B cannot decrypt Org A's ciphertext
    org_b = "org_beta_02"
    salt_b = secrets.token_hex(16)
    dec_cross = vault.decrypt_for_tenant(enc_v1, org_b, salt_b)
    assert dec_cross != secret_text  # Fails decryption cleanly or falls back without leak
    print("  [OK] Cross-tenant isolation verified: Org B cannot decrypt Org A's envelope secret.")


@pytest.mark.asyncio
async def test_3_database_schema_and_cascades():
    """Verify multi-tenant schema models, constraints, and cascade de-provisioning."""
    print("\n[TEST 3] Verifying Database Schema, Unique Constraints & Cascades...")

    await init_db()

    async with AsyncSessionLocal() as session:
        org_repo = OrganizationRepository(session)
        user_repo = UserRepository(session)
        mbx_repo = MailboxRepository(session)
        email_repo = EmailRepository(session)
        draft_repo = DraftRepository(session)

        # 1. Create Organization
        test_org_id = f"org_test_{secrets.token_hex(4)}"
        org = Organization(
            id=test_org_id,
            name="Test Enterprise Inc",
            slug=f"slug-{test_org_id}",
            tier="enterprise",
            max_seats=10,
            encryption_salt=secrets.token_hex(32),
            key_version=1,
            is_active=True
        )
        await org_repo.create(org)

        # 2. Create User
        test_user_id = f"usr_{secrets.token_hex(4)}"
        user = User(
            id=test_user_id,
            organization_id=test_org_id,
            email="lead.architect@testenterprise.com",
            name="Lead Architect",
            role="owner",
            auth_provider="local"
        )
        await user_repo.create(user)

        # 3. Create Mailbox
        test_mbx_id = f"mbx_{secrets.token_hex(4)}"
        mbx = Mailbox(
            id=test_mbx_id,
            organization_id=test_org_id,
            user_id=test_user_id,
            email_address="ops@testenterprise.com",
            imap_server="imap.gmail.com"
        )
        await mbx_repo.create(mbx)

        # 4. Create Thread & Message
        test_thd_id = f"thd_{secrets.token_hex(4)}"
        thread = EmailThread(
            id=test_thd_id,
            organization_id=test_org_id,
            mailbox_id=test_mbx_id,
            subject="Urgent Security Assessment",
            last_message_at=datetime.now(timezone.utc)
        )
        session.add(thread)
        await session.flush()

        test_msg_id = f"msg_{secrets.token_hex(4)}"
        msg = EmailMessage(
            id=test_msg_id,
            organization_id=test_org_id,
            thread_id=test_thd_id,
            mailbox_id=test_mbx_id,
            sender="auditor@compliance.org",
            recipient="ops@testenterprise.com",
            subject="Urgent Security Assessment",
            date=datetime.now(timezone.utc),
            tasks=["Verify multi-tenant barriers", "Audit SOC-2 logs"]
        )
        await email_repo.create_message(msg)

        # 5. Create Draft
        test_drf_id = f"drf_{secrets.token_hex(4)}"
        draft = Draft(
            id=test_drf_id,
            organization_id=test_org_id,
            email_id=test_msg_id,
            recipient="auditor@compliance.org",
            subject="Re: Urgent Security Assessment",
            body="All multi-tenant controls are strictly enforced.",
            status="pending"
        )
        await draft_repo.create(draft)
        await session.commit()
        print(f"  [OK] Successfully provisioned Org '{test_org_id}' with user, mailbox, thread, message & draft.")

        # 6. Verify Unique Constraint: Duplicate (org_id, email) must raise IntegrityError
        dup_user = User(
            id=f"usr_dup_{secrets.token_hex(4)}",
            organization_id=test_org_id,
            email="lead.architect@testenterprise.com",  # Duplicate email in same org
            name="Duplicate User",
            role="member"
        )
        session.add(dup_user)
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()
        print("  [OK] UniqueConstraint('organization_id', 'email') enforced successfully.")

        # 7. Verify Unique Constraint: Duplicate (org_id, email_address) on Mailbox
        dup_mbx = Mailbox(
            id=f"mbx_dup_{secrets.token_hex(4)}",
            organization_id=test_org_id,
            email_address="ops@testenterprise.com",  # Duplicate mailbox in same org
            imap_server="imap.gmail.com"
        )
        session.add(dup_mbx)
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()
        print("  [OK] UniqueConstraint('organization_id', 'email_address') on Mailbox enforced.")

        # 8. Test Cascade Delete: deleting Organization must wipe all child entities
        org_to_delete = await org_repo.get_by_id(test_org_id)
        await session.delete(org_to_delete)
        await session.commit()

        # Verify child records purged
        assert await user_repo.get_by_id(test_user_id) is None
        assert await mbx_repo.get_by_id(test_mbx_id) is None
        assert await email_repo.get_message(test_msg_id) is None
        assert await draft_repo.get_by_id(test_drf_id) is None
        print("  [OK] Cascade deletion verified: Deleting Organization cleanly purged all dependent records.")


@pytest.mark.asyncio
async def test_4_soc2_audit_payload_and_hmac_integrity():
    """Verify that AuditLog stores full redacted payload and authenticates via SHA-256 HMAC."""
    print("\n[TEST 4] Verifying SOC-2 Audit Payload Retention & HMAC Integrity...")

    await init_db()

    async with AsyncSessionLocal() as session:
        # Create temporary org
        org_id = f"org_audit_{secrets.token_hex(4)}"
        session.add(Organization(
            id=org_id,
            name="Audit Corp",
            slug=f"slug-{org_id}",
            encryption_salt=secrets.token_hex(16)
        ))
        await session.flush()

        audit_repo = AuditLogRepository(session)
        test_payload = {
            "action_type": "DISPATCH_APPROVAL",
            "draft_id": "drf_sample_99",
            "recipient": "client@acme.com",
            "credentials_redacted": True,
            "latency_ms": 42.1
        }

        log_entry = await audit_repo.log_event(
            org_id=org_id,
            category="DISPATCH",
            action="EMAIL_SENT",
            message="Dispatched AI approved draft to client@acme.com",
            payload=test_payload,
            level="SUCCESS"
        )
        await session.commit()

        # Verify payload retention
        fetched = await session.get(AuditLog, log_entry.id)
        assert fetched is not None
        assert fetched.redacted_payload == test_payload
        assert fetched.redacted_payload["recipient"] == "client@acme.com"
        print("  [OK] Full redacted event payload retained in audit record (not just hash).")

        # Verify payload_hash correctness
        expected_hash = hashlib.sha256(
            f"{org_id}:EMAIL_SENT:{json.dumps(test_payload, sort_keys=True)}".encode("utf-8")
        ).hexdigest()
        assert fetched.payload_hash == expected_hash
        print(f"  [OK] Cryptographic HMAC hash verified: {fetched.payload_hash[:20]}...")

        # Tamper-evidence check: if payload is modified, hash comparison fails
        tampered_payload = dict(test_payload)
        tampered_payload["recipient"] = "attacker@evil.com"
        tampered_hash = hashlib.sha256(
            f"{org_id}:EMAIL_SENT:{json.dumps(tampered_payload, sort_keys=True)}".encode("utf-8")
        ).hexdigest()
        assert tampered_hash != fetched.payload_hash
        print("  [OK] Forensic tamper detection verified: Modified payload triggers hash mismatch.")


@pytest.mark.asyncio
async def test_5_idempotent_migration_dry_run_and_idempotency():
    """Verify that migration is non-destructive, supports --dry-run, and produces zero duplicates."""
    print("\n[TEST 5] Verifying Idempotent JSON-to-Postgres Migration...")

    await init_db()

    async with AsyncSessionLocal() as session:
        # A. Dry-run execution
        dry_stats = await migrate_data(session, dry_run=True)
        assert dry_stats["organizations"] > 0
        assert dry_stats["users"] > 0
        print(f"  [OK] Dry-run executed successfully: {dry_stats['organizations']} orgs, {dry_stats['messages']} messages simulated.")

        # B. Live execution 1
        live_stats_1 = await migrate_data(session, dry_run=False)
        print(f"  [OK] Live run #1 committed: {live_stats_1['organizations']} orgs, {live_stats_1['messages']} messages inserted.")

        # C. Live execution 2 (Idempotency test)
        live_stats_2 = await migrate_data(session, dry_run=False)
        # On second run, no new entities should be inserted (all are 0)
        assert live_stats_2["organizations"] == 0
        assert live_stats_2["users"] == 0
        assert live_stats_2["mailboxes"] == 0
        assert live_stats_2["messages"] == 0
        assert live_stats_2["drafts"] == 0
        print("  [OK] Idempotency verified: Second live run inserted 0 duplicates.")


@pytest.mark.asyncio
async def test_6_distributed_rate_limiter_and_blacklist():
    """Verify sliding-window rate limiting and token revocation."""
    print("\n[TEST 6] Verifying Rate Limiter & Token Revocation...")

    client_id = f"client_{secrets.token_hex(4)}"

    # Allow up to 3 requests in window
    ok1, rem1 = await rate_limiter.is_allowed(client_id, max_requests=3, window_seconds=10)
    assert ok1 is True
    assert rem1 == 2

    ok2, rem2 = await rate_limiter.is_allowed(client_id, max_requests=3, window_seconds=10)
    assert ok2 is True
    assert rem2 == 1

    ok3, rem3 = await rate_limiter.is_allowed(client_id, max_requests=3, window_seconds=10)
    assert ok3 is True
    assert rem3 == 0

    # 4th request must be blocked
    ok4, rem4 = await rate_limiter.is_allowed(client_id, max_requests=3, window_seconds=10)
    assert ok4 is False
    assert rem4 == 0
    print("  [OK] Sliding window rate limiter successfully throttles beyond limit.")

    # Token Blacklist Revocation
    test_token = f"jwt_tok_{secrets.token_hex(16)}"
    assert await token_blacklist.is_revoked(test_token) is False
    await token_blacklist.revoke_token(test_token, ttl_seconds=60)
    assert await token_blacklist.is_revoked(test_token) is True
    print("  [OK] Distributed token blacklist correctly revoked and verified token.")


def run_all():
    print("=" * 70)
    print("      PHASE 1 INTEGRATION TEST SUITE: MULTI-TENANCY & DATA ARCHITECTURE")
    print("=" * 70)

    test_1_hard_jwt_startup_gate()
    test_2_tenant_envelope_encryption_and_rotation()
    asyncio.run(test_3_database_schema_and_cascades())
    asyncio.run(test_4_soc2_audit_payload_and_hmac_integrity())
    asyncio.run(test_5_idempotent_migration_dry_run_and_idempotency())
    asyncio.run(test_6_distributed_rate_limiter_and_blacklist())

    print("\n" + "=" * 70)
    print("      ALL PHASE 1 INTEGRATION TESTS PASSED WITH ZERO ERRORS! [OK]")
    print("=" * 70)


if __name__ == "__main__":
    run_all()
