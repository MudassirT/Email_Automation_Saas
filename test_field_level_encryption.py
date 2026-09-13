"""
Field-Level Encryption Tests
==============================
Validates the EncryptedTextField TypeDecorator and EncryptionContext helpers
introduced in email_service/db/models.py.

Run with:
    python -m pytest test_field_level_encryption.py -v
"""

import pytest
from email_service.db.models import (
    EncryptedTextField,
    set_encryption_context,
    clear_encryption_context,
    get_encryption_context,
)
from email_service.security import vault

ORG_ID  = "test_org_enc_01"
SALT    = "aabbccddeeff00112233445566778899"
VERSION = 1
PLAIN   = "Meeting at 3pm regarding Q4 budget — Alice"


@pytest.fixture(autouse=True)
def reset_context():
    clear_encryption_context()
    yield
    clear_encryption_context()


@pytest.fixture
def field():
    return EncryptedTextField()


def test_set_and_get_context():
    set_encryption_context(ORG_ID, SALT, VERSION)
    ctx = get_encryption_context()
    assert ctx == (ORG_ID, SALT, VERSION)


def test_clear_context():
    set_encryption_context(ORG_ID, SALT, VERSION)
    clear_encryption_context()
    assert get_encryption_context() is None


def test_encrypt_with_context(field):
    set_encryption_context(ORG_ID, SALT, VERSION)
    result = field.process_bind_param(PLAIN, dialect=None)
    assert result.startswith(f"ENC::v{VERSION}::")
    assert result != PLAIN


def test_encrypt_none_returns_none(field):
    set_encryption_context(ORG_ID, SALT, VERSION)
    assert field.process_bind_param(None, dialect=None) is None


def test_encrypt_without_context_stores_plaintext(field):
    result = field.process_bind_param(PLAIN, dialect=None)
    assert result == PLAIN


def test_encrypt_already_encrypted_is_idempotent(field):
    set_encryption_context(ORG_ID, SALT, VERSION)
    first_pass = field.process_bind_param(PLAIN, dialect=None)
    second_pass = field.process_bind_param(first_pass, dialect=None)
    assert second_pass == first_pass


def test_decrypt_with_context(field):
    set_encryption_context(ORG_ID, SALT, VERSION)
    ciphertext = field.process_bind_param(PLAIN, dialect=None)
    decrypted = field.process_result_value(ciphertext, dialect=None)
    assert decrypted == PLAIN


def test_decrypt_plaintext_passthrough(field):
    set_encryption_context(ORG_ID, SALT, VERSION)
    result = field.process_result_value("Hello world", dialect=None)
    assert result == "Hello world"


def test_decrypt_without_context_returns_ciphertext(field):
    set_encryption_context(ORG_ID, SALT, VERSION)
    ciphertext = field.process_bind_param(PLAIN, dialect=None)
    clear_encryption_context()
    result = field.process_result_value(ciphertext, dialect=None)
    assert result.startswith("ENC::")


def test_decrypt_none_returns_none(field):
    set_encryption_context(ORG_ID, SALT, VERSION)
    assert field.process_result_value(None, dialect=None) is None


def test_roundtrip_different_versions(field):
    """Key versioning: vault auto-detects version from ENC::v{n}:: prefix.
    Ciphertext prefix must correctly label the version used."""
    set_encryption_context(ORG_ID, SALT, 1)
    ciphertext_v1 = field.process_bind_param(PLAIN, dialect=None)
    # Label must be ENC::v1::
    assert ciphertext_v1.startswith("ENC::v1::"), "Version must be embedded in ciphertext label"
    # v2 encrypted ciphertext must have different prefix
    set_encryption_context(ORG_ID, SALT, 2)
    ciphertext_v2 = field.process_bind_param(PLAIN, dialect=None)
    assert ciphertext_v2.startswith("ENC::v2::"), "v2 ciphertext must carry v2 label"
    # The two ciphertexts must differ (different keys)
    assert ciphertext_v1 != ciphertext_v2, "v1 and v2 ciphertexts must differ"


def test_roundtrip_different_orgs(field):
    set_encryption_context("org_A", SALT, VERSION)
    ct_a = field.process_bind_param(PLAIN, dialect=None)
    set_encryption_context("org_B", SALT, VERSION)
    ct_b = field.process_bind_param(PLAIN, dialect=None)
    assert ct_a != ct_b
    result = field.process_result_value(ct_a, dialect=None)
    assert result != PLAIN, "Cross-tenant decryption must fail"


def test_roundtrip_unicode(field):
    unicode_text = "Subject: 会议 Rocket — Ünïcödé tëst"
    set_encryption_context(ORG_ID, SALT, VERSION)
    ct = field.process_bind_param(unicode_text, dialect=None)
    result = field.process_result_value(ct, dialect=None)
    assert result == unicode_text


def test_reencrypt_field_helper():
    from email_service.db.key_rotation import _reencrypt_field
    ct_v1 = vault.encrypt_for_tenant(PLAIN, ORG_ID, SALT, version=1)
    ct_v2 = _reencrypt_field(ct_v1, ORG_ID, SALT, from_version=1, to_version=2)
    assert ct_v2 is not None
    assert ct_v2.startswith("ENC::v2::")
    decrypted = vault.decrypt_for_tenant(ct_v2, ORG_ID, SALT, version=2)
    assert decrypted == PLAIN


def test_reencrypt_field_skips_already_at_target():
    from email_service.db.key_rotation import _reencrypt_field
    ct_v2 = vault.encrypt_for_tenant(PLAIN, ORG_ID, SALT, version=2)
    result = _reencrypt_field(ct_v2, ORG_ID, SALT, from_version=1, to_version=2)
    assert result is None


def test_reencrypt_field_skips_plaintext():
    from email_service.db.key_rotation import _reencrypt_field
    result = _reencrypt_field("plain text", ORG_ID, SALT, from_version=1, to_version=2)
    assert result is None

