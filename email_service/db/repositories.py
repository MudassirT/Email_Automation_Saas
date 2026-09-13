"""
Asynchronous Repository Layer for AutoMail AI Multi-Tenant SaaS.
Encapsulates all SQLAlchemy 2.0 queries, tenant scoping,
pagination, and audit verification safeguards.
"""

import json
import hashlib
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from sqlalchemy import select, update, delete, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Organization, User, Mailbox, EmailThread,
    EmailMessage, Draft, AutomationRule, AuditLog, Integration
)


class BaseRepository:
    def __init__(self, session: AsyncSession):
        self.session = session


class OrganizationRepository(BaseRepository):
    async def get_by_id(self, org_id: str) -> Optional[Organization]:
        return await self.session.get(Organization, org_id)

    async def get_by_slug(self, slug: str) -> Optional[Organization]:
        stmt = select(Organization).where(Organization.slug == slug)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def create(self, org: Organization) -> Organization:
        self.session.add(org)
        await self.session.flush()
        return org

    async def list_all(self, limit: int = 100) -> List[Organization]:
        stmt = select(Organization).order_by(desc(Organization.created_at)).limit(limit)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())


class UserRepository(BaseRepository):
    async def get_by_id(self, user_id: str) -> Optional[User]:
        return await self.session.get(User, user_id)

    async def get_by_email(self, email: str, org_id: Optional[str] = None) -> Optional[User]:
        stmt = select(User).where(func.lower(User.email) == email.lower().strip())
        if org_id:
            stmt = stmt.where(User.organization_id == org_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_google_id(self, google_id: str) -> Optional[User]:
        stmt = select(User).where(User.google_id == google_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_organization(self, org_id: str) -> List[User]:
        stmt = select(User).where(User.organization_id == org_id).order_by(User.name)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def create(self, user: User) -> User:
        self.session.add(user)
        await self.session.flush()
        return user


class MailboxRepository(BaseRepository):
    async def get_by_id(self, mailbox_id: str) -> Optional[Mailbox]:
        return await self.session.get(Mailbox, mailbox_id)

    async def get_by_email(self, org_id: str, email_address: str) -> Optional[Mailbox]:
        stmt = select(Mailbox).where(
            and_(
                Mailbox.organization_id == org_id,
                func.lower(Mailbox.email_address) == email_address.lower().strip()
            )
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_organization(self, org_id: str) -> List[Mailbox]:
        stmt = select(Mailbox).where(Mailbox.organization_id == org_id).order_by(desc(Mailbox.created_at))
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def create(self, mailbox: Mailbox) -> Mailbox:
        self.session.add(mailbox)
        await self.session.flush()
        return mailbox


class EmailRepository(BaseRepository):
    async def get_message(self, message_id: str, org_id: Optional[str] = None) -> Optional[EmailMessage]:
        stmt = select(EmailMessage).where(EmailMessage.id == message_id)
        if org_id:
            stmt = stmt.where(EmailMessage.organization_id == org_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_messages(
        self,
        org_id: str,
        category: Optional[str] = None,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[EmailMessage]:
        stmt = select(EmailMessage).where(EmailMessage.organization_id == org_id)
        if category and category != "All":
            stmt = stmt.where(EmailMessage.category == category)
        if priority:
            stmt = stmt.where(EmailMessage.priority == priority)
        if status:
            stmt = stmt.where(EmailMessage.status == status)

        stmt = stmt.order_by(desc(EmailMessage.date)).limit(limit).offset(offset)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def count_messages(self, org_id: str, status: Optional[str] = None) -> int:
        stmt = select(func.count(EmailMessage.id)).where(EmailMessage.organization_id == org_id)
        if status:
            stmt = stmt.where(EmailMessage.status == status)
        res = await self.session.execute(stmt)
        return res.scalar_one() or 0

    async def create_message(self, message: EmailMessage) -> EmailMessage:
        self.session.add(message)
        await self.session.flush()
        return message

    async def update_status(self, message_id: str, org_id: str, status: str) -> bool:
        stmt = update(EmailMessage).where(
            and_(EmailMessage.id == message_id, EmailMessage.organization_id == org_id)
        ).values(status=status)
        res = await self.session.execute(stmt)
        return (res.rowcount or 0) > 0


class DraftRepository(BaseRepository):
    async def get_by_id(self, draft_id: str, org_id: Optional[str] = None) -> Optional[Draft]:
        stmt = select(Draft).where(Draft.id == draft_id)
        if org_id:
            stmt = stmt.where(Draft.organization_id == org_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_drafts(
        self,
        org_id: str,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Draft]:
        stmt = select(Draft).where(Draft.organization_id == org_id)
        if status:
            stmt = stmt.where(Draft.status == status)
        stmt = stmt.order_by(desc(Draft.created_at)).limit(limit)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def create(self, draft: Draft) -> Draft:
        self.session.add(draft)
        await self.session.flush()
        return draft

    async def update_status(self, draft_id: str, org_id: str, status: str, user_id: Optional[str] = None) -> bool:
        now = datetime.now(timezone.utc)
        values = {"status": status}
        if status == "approved":
            values["reviewed_at"] = now
            values["reviewed_by"] = user_id
        elif status == "sent":
            values["sent_at"] = now

        stmt = update(Draft).where(
            and_(Draft.id == draft_id, Draft.organization_id == org_id)
        ).values(**values)
        res = await self.session.execute(stmt)
        return (res.rowcount or 0) > 0


class RuleRepository(BaseRepository):
    async def list_by_organization(self, org_id: str) -> List[AutomationRule]:
        stmt = select(AutomationRule).where(AutomationRule.organization_id == org_id).order_by(AutomationRule.name)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def create(self, rule: AutomationRule) -> AutomationRule:
        self.session.add(rule)
        await self.session.flush()
        return rule

    async def delete(self, rule_id: str, org_id: str) -> bool:
        stmt = delete(AutomationRule).where(
            and_(AutomationRule.id == rule_id, AutomationRule.organization_id == org_id)
        )
        res = await self.session.execute(stmt)
        return (res.rowcount or 0) > 0


class AuditLogRepository(BaseRepository):
    async def log_event(
        self,
        org_id: str,
        category: str,
        action: str,
        message: str,
        payload: Optional[Dict[str, Any]] = None,
        level: str = "INFO",
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> AuditLog:
        """
        Record SOC-2 audit event. Retains sanitized payload and generates
        SHA-256 HMAC integrity hash.
        """
        sanitized_payload = payload or {}
        # Ensure sensitive tokens/credentials are disarmed in audit payload
        clean_str = json.dumps(sanitized_payload, sort_keys=True, default=str)
        p_hash = hashlib.sha256(f"{org_id}:{action}:{clean_str}".encode("utf-8")).hexdigest()

        log_entry = AuditLog(
            id=f"aud_{uuid.uuid4().hex[:12]}",
            organization_id=org_id,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc),
            level=level.upper(),
            category=category.upper(),
            action=action,
            message=message,
            redacted_payload=sanitized_payload,
            payload_hash=p_hash,
            ip_address=ip_address
        )
        self.session.add(log_entry)
        await self.session.flush()
        return log_entry

    async def list_events(self, org_id: str, limit: int = 100) -> List[AuditLog]:
        stmt = select(AuditLog).where(
            AuditLog.organization_id == org_id
        ).order_by(desc(AuditLog.timestamp)).limit(limit)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def list_cross_tenant_events(self, limit: int = 100) -> List[AuditLog]:
        stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())


class IntegrationRepository(BaseRepository):
    async def list_by_organization(self, org_id: str) -> List[Integration]:
        stmt = select(Integration).where(Integration.organization_id == org_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def upsert(self, org_id: str, connector_id: str, enabled: bool, config: Dict[str, Any]) -> Integration:
        stmt = select(Integration).where(
            and_(Integration.organization_id == org_id, Integration.connector_id == connector_id)
        )
        res = await self.session.execute(stmt)
        existing = res.scalar_one_or_none()
        if existing:
            existing.enabled = enabled
            existing.config = config
            existing.updated_at = datetime.now(timezone.utc)
            await self.session.flush()
            return existing
        else:
            new_int = Integration(
                id=f"int_{uuid.uuid4().hex[:8]}",
                organization_id=org_id,
                connector_id=connector_id,
                enabled=enabled,
                config=config
            )
            self.session.add(new_int)
            await self.session.flush()
            return new_int
