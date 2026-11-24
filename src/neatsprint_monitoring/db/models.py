"""Monitoring models: devices, sessions, screenshots and audit records."""

from __future__ import annotations

import uuid
from datetime import datetime

from neatsprint_lib.db import Base, TenantMixin, TimestampMixin
from neatsprint_lib.events import OutboxEvent as OutboxEvent  # noqa: F401 - register table
from neatsprint_lib.ids import new_id
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

DEVICE_STATES = ("ACTIVE", "SUSPENDED", "REVOKED")
SESSION_STATES = ("ACTIVE", "STOPPED")
SCREENSHOT_STATES = ("PENDING", "VISIBLE", "DELETED", "EXPIRED")
COMMAND_TYPES = ("SUSPEND", "REVOKE", "WIPE")


class Device(Base, TenantMixin, TimestampMixin):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "user_id", "fingerprint_hash", name="uq_device_fingerprint"
        ),
        Index("ix_devices_user", "tenant_id", "user_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=new_id
    )
    user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    wipe_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MonitoringSession(Base, TenantMixin, TimestampMixin):
    __tablename__ = "monitoring_sessions"
    __table_args__ = (
        Index("ix_monitor_sessions_user", "tenant_id", "user_id", "started_at"),
        Index(
            "ux_monitor_session_work",
            "tenant_id",
            "work_session_id",
            unique=True,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=new_id
    )
    user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    work_session_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL")
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")


class Screenshot(Base, TenantMixin, TimestampMixin):
    __tablename__ = "screenshots"
    __table_args__ = (
        Index("ix_shots_owner_pending", "tenant_id", "user_id", "state", "captured_at"),
        Index("ix_shots_manager", "tenant_id", "state", "visible_after", "captured_at"),
        Index("ix_shots_session", "session_id", "captured_at"),
        CheckConstraint(
            "deleted_by_user = false OR (storage_key IS NULL AND wrapped_key IS NULL)",
            name="ck_deleted_has_no_blob",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=new_id
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("monitoring_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    storage_key: Mapped[str | None] = mapped_column(String(512))
    kms_key_id: Mapped[str | None] = mapped_column(String(64))
    wrapped_key: Mapped[str | None] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    width: Mapped[int] = mapped_column(Integer, nullable=False)
    height: Mapped[int] = mapped_column(Integer, nullable=False)
    display_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    visible_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deleted_by_user: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    retention_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ActivityHeartbeat(Base, TenantMixin):
    __tablename__ = "activity_heartbeats"
    __table_args__ = (Index("ix_heartbeats_session", "session_id", "recorded_at"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=new_id
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("monitoring_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    active_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    idle_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    device_state: Mapped[str | None] = mapped_column(String(32))


class DeletionAudit(Base, TenantMixin):
    __tablename__ = "deletion_audit"
    __table_args__ = (Index("ix_deletion_audit_shot", "screenshot_id"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=new_id
    )
    screenshot_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_source: Mapped[str] = mapped_column(String(16), nullable=False)
    blob_confirmed_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    embedding_confirmed_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False)


class ScreenshotView(Base, TenantMixin):
    __tablename__ = "screenshot_views"
    __table_args__ = (Index("ix_screenshot_views_shot", "screenshot_id", "viewed_at"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=new_id
    )
    screenshot_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    viewer_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    viewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="WEB")


class DeviceCommand(Base, TenantMixin):
    __tablename__ = "device_commands"
    __table_args__ = (Index("ix_device_commands_device", "device_id", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=new_id
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
