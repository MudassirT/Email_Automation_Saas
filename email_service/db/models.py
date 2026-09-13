"""
SQLAlchemy 2.0 Async Models for AutoMail AI Enterprise SaaS.
Full multi-tenant data architecture with foreign key cascades,
b-tree composite indexes, envelope encryption metadata, and audit integrity safeguards.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    String, Text, Integer, Boolean, DateTime, ForeignKey,
    UniqueConstraint, Index, func, JSON
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship
)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------
# 1. ORGANIZATIONS (Tenant Root Entity)
# --------------------------------------------------------------------------
class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. org_4d670be2
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    tier: Mapped[str] = mapped_column(String(50), default="free", nullable=False)  # free, pro, enterprise
    max_seats: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    
    # Cryptographic Envelope Encryption
    encryption_salt: Mapped[str] = mapped_column(String(64), nullable=False)  # Org-specific PBKDF2 salt
    key_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)  # Enables zero-downtime key rotation
    
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships (Cascade deletes ensure clean tenant de-provisioning)
    users: Mapped[List["User"]] = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    mailboxes: Mapped[List["Mailbox"]] = relationship("Mailbox", back_populates="organization", cascade="all, delete-orphan")
    threads: Mapped[List["EmailThread"]] = relationship("EmailThread", back_populates="organization", cascade="all, delete-orphan")
    rules: Mapped[List["AutomationRule"]] = relationship("AutomationRule", back_populates="organization", cascade="all, delete-orphan")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")
    integrations: Mapped[List["Integration"]] = relationship("Integration", back_populates="organization", cascade="all, delete-orphan")


# --------------------------------------------------------------------------
# 2. USERS & MEMBERSHIPS (RBAC & Auth)
# --------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. usr_leadarchitec_4d670be2
    organization_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Nullable for SSO/OAuth
    role: Mapped[str] = mapped_column(String(50), default="member", nullable=False)  # owner, admin, manager, member
    auth_provider: Mapped[str] = mapped_column(String(50), default="local", nullable=False)  # local, google, azure_ad
    google_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    picture_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="users")
    mailboxes: Mapped[List["Mailbox"]] = relationship("Mailbox", back_populates="owner_user")

    __table_args__ = (
        UniqueConstraint("organization_id", "email", name="uq_org_user_email"),
        Index("ix_user_org_role", "organization_id", "role"),
    )


# --------------------------------------------------------------------------
# 3. MAILBOXES (IMAP/SMTP & OAuth Mail Accounts)
# --------------------------------------------------------------------------
class Mailbox(Base):
    __tablename__ = "mailboxes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. mbx_01h8abc
    organization_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    email_address: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    provider: Mapped[str] = mapped_column(String(50), default="gmail", nullable=False)  # gmail, outlook, custom_imap
    connection_type: Mapped[str] = mapped_column(String(50), default="app_password", nullable=False)
    
    # Encrypted under the Organization's envelope key
    encrypted_credentials: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    imap_server: Mapped[str] = mapped_column(String(255), default="imap.gmail.com", nullable=False)
    imap_port: Mapped[int] = mapped_column(Integer, default=993, nullable=False)
    smtp_server: Mapped[str] = mapped_column(String(255), default="smtp.gmail.com", nullable=False)
    smtp_port: Mapped[int] = mapped_column(Integer, default=587, nullable=False)
    
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_uid: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)  # active, paused, error
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="mailboxes")
    owner_user: Mapped[Optional["User"]] = relationship("User", back_populates="mailboxes")
    threads: Mapped[List["EmailThread"]] = relationship("EmailThread", back_populates="mailbox", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("organization_id", "email_address", name="uq_org_mailbox_email"),
        Index("ix_mailbox_org_status", "organization_id", "status"),
    )


# --------------------------------------------------------------------------
# 4. EMAIL THREADS & CONVERSATIONS
# --------------------------------------------------------------------------
class EmailThread(Base):
    __tablename__ = "email_threads"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. thd_9a8b7c
    organization_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    mailbox_id: Mapped[str] = mapped_column(String(64), ForeignKey("mailboxes.id", ondelete="CASCADE"), nullable=False, index=True)

    external_thread_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_message_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    status: Mapped[str] = mapped_column(String(50), default="unread", nullable=False, index=True)  # unread, read, archived
    priority: Mapped[str] = mapped_column(String(50), default="Normal", nullable=False, index=True)  # Urgent, High, Normal, Low
    category: Mapped[str] = mapped_column(String(50), default="General", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="threads")
    mailbox: Mapped["Mailbox"] = relationship("Mailbox", back_populates="threads")
    messages: Mapped[List["EmailMessage"]] = relationship("EmailMessage", back_populates="thread", cascade="all, delete-orphan")
    drafts: Mapped[List["Draft"]] = relationship("Draft", back_populates="thread")

    __table_args__ = (
        Index("ix_thread_org_status", "organization_id", "status"),
        Index("ix_thread_org_priority", "organization_id", "priority"),
        Index("ix_thread_org_category", "organization_id", "category"),
    )


# --------------------------------------------------------------------------
# 5. EMAIL MESSAGES (Ingested Emails with AI Briefings & Tasks)
# --------------------------------------------------------------------------
class EmailMessage(Base):
    __tablename__ = "email_messages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. msg_sample_01
    organization_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    thread_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_threads.id", ondelete="CASCADE"), nullable=False, index=True)
    mailbox_id: Mapped[str] = mapped_column(String(64), ForeignKey("mailboxes.id", ondelete="CASCADE"), nullable=False, index=True)

    uid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    message_id_header: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    sender: Mapped[str] = mapped_column(Text, nullable=False)
    sender_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sender_organization: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    recipient: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    # AI Classification & Briefings
    category: Mapped[str] = mapped_column(String(50), default="General", nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(50), default="Normal", nullable=False, index=True)
    sentiment: Mapped[str] = mapped_column(String(50), default="Neutral", nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compressed_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    core_intent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action_needed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tasks: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    ai_automated_actions: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    # Security & Threat Defense
    prompt_shield_flagged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    prompt_shield_threat: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="unread", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    thread: Mapped["EmailThread"] = relationship("EmailThread", back_populates="messages")
    drafts: Mapped[List["Draft"]] = relationship("Draft", back_populates="email_message", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_msg_org_date", "organization_id", "date"),
        Index("ix_msg_org_priority", "organization_id", "priority"),
    )


# --------------------------------------------------------------------------
# 6. DRAFTS & APPROVAL QUEUE
# --------------------------------------------------------------------------
class Draft(Base):
    __tablename__ = "drafts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. draft_sample_01
    organization_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("email_messages.id", ondelete="CASCADE"), nullable=True, index=True)
    thread_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("email_threads.id", ondelete="SET NULL"), nullable=True, index=True)

    recipient: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    tone: Mapped[str] = mapped_column(String(50), default="Professional", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False, index=True)  # pending, approved, rejected, sent
    
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    email_message: Mapped[Optional["EmailMessage"]] = relationship("EmailMessage", back_populates="drafts")
    thread: Mapped[Optional["EmailThread"]] = relationship("EmailThread", back_populates="drafts")

    __table_args__ = (
        Index("ix_draft_org_status", "organization_id", "status"),
    )


# --------------------------------------------------------------------------
# 7. AUTOMATION RULES
# --------------------------------------------------------------------------
class AutomationRule(Base):
    __tablename__ = "automation_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. rule_urgent_client
    organization_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    condition_field: Mapped[str] = mapped_column(String(50), nullable=False)
    condition_operator: Mapped[str] = mapped_column(String(50), nullable=False)
    condition_value: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    action_param: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="rules")

    __table_args__ = (
        Index("ix_rule_org_enabled", "organization_id", "enabled"),
    )


# --------------------------------------------------------------------------
# 8. AUDIT LOGS (SOC-2 Track Redacted Payload + Integrity Checksum)
# --------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. aud_1a2b3c
    organization_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(20), default="INFO", nullable=False, index=True)  # INFO, WARNING, ERROR, SUCCESS
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # AUTH, SECURITY, DISPATCH, INTEGRATION, RULE, AI
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    
    # SOC-2 Compliance: Retain actual sanitized payload + tamper-evident hash
    redacted_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 HMAC for forensic validation
    
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_org_timestamp", "organization_id", "timestamp"),
        Index("ix_audit_org_category", "organization_id", "category"),
    )


# --------------------------------------------------------------------------
# 9. INTEGRATIONS & ECOSYSTEM CONNECTORS
# --------------------------------------------------------------------------
class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    connector_id: Mapped[str] = mapped_column(String(50), nullable=False)  # slack, teams, jira, salesforce, siem
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="integrations")

    __table_args__ = (
        UniqueConstraint("organization_id", "connector_id", name="uq_org_connector"),
    )
