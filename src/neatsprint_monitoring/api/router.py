"""Monitoring API: devices, sessions, screenshots, privacy and transparency."""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from neatsprint_lib.auth import Principal, get_principal, require_permission
from neatsprint_lib.db import get_tenant_session
from neatsprint_lib.errors import ApiError
from neatsprint_lib.events import enqueue
from neatsprint_lib.ids import new_id
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from neatsprint_monitoring.api.schemas import (
    DeviceRegister,
    Heartbeat,
    SessionStart,
)
from neatsprint_monitoring.db.models import (
    ActivityHeartbeat,
    DeletionAudit,
    Device,
    DeviceCommand,
    MonitoringSession,
    Screenshot,
    ScreenshotView,
)
from neatsprint_monitoring.services import crypto, storage, worklog
from neatsprint_monitoring.services.team_scope import scope_for_user
from neatsprint_monitoring.services.upload_guard import validate_upload, virus_scan

router = APIRouter(tags=["monitor"])

SessionDep = Annotated[AsyncSession, Depends(get_tenant_session)]
CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
TimerPerm = Annotated[Principal, Depends(require_permission("work:timer:start"))]
MonitorView = Annotated[Principal, Depends(require_permission("monitor:data:view_team"))]
DeviceManage = Annotated[Principal, Depends(require_permission("monitor:device:manage"))]

ALLOWED_TYPES = {"image/png", "image/jpeg", "image/webp"}


def envelope(request: Request, data: object, **meta: object) -> dict[str, object]:
    return {
        "data": data,
        "meta": {"request_id": getattr(request.state, "request_id", None), **meta},
    }


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _device_payload(device: Device) -> dict[str, object]:
    return {
        "id": str(device.id),
        "user_id": str(device.user_id),
        "name": device.name,
        "platform": device.platform,
        "status": device.status,
        "fingerprint_hash": device.fingerprint_hash,
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
        "revoked_at": device.revoked_at.isoformat() if device.revoked_at else None,
        "wipe_requested_at": (
            device.wipe_requested_at.isoformat() if device.wipe_requested_at else None
        ),
    }


def _session_payload(monitor_session: MonitoringSession) -> dict[str, object]:
    return {
        "id": str(monitor_session.id),
        "user_id": str(monitor_session.user_id),
        "work_session_id": str(monitor_session.work_session_id),
        "device_id": str(monitor_session.device_id) if monitor_session.device_id else None,
        "state": monitor_session.state,
        "started_at": monitor_session.started_at.isoformat(),
        "ended_at": (
            monitor_session.ended_at.isoformat() if monitor_session.ended_at else None
        ),
    }


def _shot_payload(screenshot: Screenshot, *, now: datetime) -> dict[str, object]:
    active = screenshot.state not in ("DELETED", "EXPIRED")
    return {
        "id": str(screenshot.id),
        "session_id": str(screenshot.session_id),
        "user_id": str(screenshot.user_id),
        "device_id": str(screenshot.device_id) if screenshot.device_id else None,
        "captured_at": screenshot.captured_at.isoformat(),
        "state": screenshot.state,
        "visible_after": screenshot.visible_after.isoformat(),
        "window_open": now < screenshot.visible_after,
        "can_delete": active and now < screenshot.visible_after,
        "width": screenshot.width,
        "height": screenshot.height,
        "display_index": screenshot.display_index,
        "size_bytes": screenshot.size_bytes,
        "deleted_by_user": screenshot.deleted_by_user,
        "deleted_at": screenshot.deleted_at.isoformat() if screenshot.deleted_at else None,
        "content_url": (
            f"/api/v1/monitor/screenshots/{screenshot.id}/content" if active else None
        ),
    }


async def _device(session: AsyncSession, tenant_id: UUID, device_id: UUID) -> Device:
    device = await session.get(Device, device_id)
    if device is None or device.tenant_id != tenant_id:
        raise ApiError(404, "not_found", "Device not found.")
    return device


async def _monitor_session(
    session: AsyncSession, tenant_id: UUID, session_id: UUID
) -> MonitoringSession:
    monitor_session = await session.get(MonitoringSession, session_id)
    if monitor_session is None or monitor_session.tenant_id != tenant_id:
        raise ApiError(404, "not_found", "Monitoring session not found.")
    return monitor_session


def _queue_command(
    session: AsyncSession, *, tenant_id: UUID, device_id: UUID, command_type: str
) -> None:
    session.add(
        DeviceCommand(
            tenant_id=tenant_id,
            device_id=device_id,
            type=command_type,
            status="PENDING",
            created_at=_now(),
        )
    )


def _range(from_date: date | None, to_date: date | None) -> tuple[datetime, datetime]:
    end_day = to_date or _now().date()
    start_day = from_date or (end_day - timedelta(days=6))
    if start_day > end_day:
        raise ApiError(422, "validation_failed", "The start date must precede the end date.")
    return (
        datetime.combine(start_day, time.min, tzinfo=UTC),
        datetime.combine(end_day + timedelta(days=1), time.min, tzinfo=UTC),
    )


async def _scoped_user_ids(
    request: Request, principal: Principal
) -> set[UUID] | None:
    if principal.can("monitor:data:view_all"):
        return None
    scope = await scope_for_user(request, principal.tenant_id, principal.user_id)
    if scope is None:
        raise ApiError(
            503, "dependency_unavailable", "Could not resolve your team scope right now."
        )
    return set(scope.user_ids)


@router.get("/ping", tags=["platform"], summary="Service liveness echo")
async def ping() -> dict[str, str]:
    return {"ping": "pong", "service": "monitoring"}


@router.post("/devices", status_code=201, summary="Register a device")
async def register_device(
    payload: DeviceRegister, principal: CurrentPrincipal, request: Request, session: SessionDep
) -> JSONResponse:
    fingerprint = hashlib.sha256(payload.public_key.encode("utf-8")).hexdigest()
    existing = (
        await session.execute(
            select(Device).where(
                Device.tenant_id == principal.tenant_id,
                Device.user_id == principal.user_id,
                Device.fingerprint_hash == fingerprint,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.name = payload.name
        existing.platform = payload.platform
        existing.public_key = payload.public_key
        existing.status = "ACTIVE"
        existing.revoked_at = None
        existing.wipe_requested_at = None
        existing.last_seen_at = _now()
        await session.commit()
        return JSONResponse(envelope(request, _device_payload(existing)))

    device = Device(
        id=new_id(),
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        name=payload.name,
        platform=payload.platform,
        public_key=payload.public_key,
        fingerprint_hash=fingerprint,
        status="ACTIVE",
        last_seen_at=_now(),
    )
    session.add(device)
    await session.commit()
    return JSONResponse(envelope(request, _device_payload(device)), status_code=201)


@router.get("/devices", summary="List my devices")
async def list_devices(
    principal: CurrentPrincipal, request: Request, session: SessionDep
) -> JSONResponse:
    rows = (
        await session.execute(
            select(Device)
            .where(
                Device.tenant_id == principal.tenant_id,
                Device.user_id == principal.user_id,
            )
            .order_by(Device.created_at)
        )
    ).scalars()
    return JSONResponse(envelope(request, [_device_payload(device) for device in rows]))


@router.post("/devices/{device_id}/suspend", summary="Suspend a device")
async def suspend_device(
    device_id: UUID,
    principal: DeviceManage,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    device = await _device(session, principal.tenant_id, device_id)
    device.status = "SUSPENDED"
    _queue_command(
        session, tenant_id=principal.tenant_id, device_id=device.id, command_type="SUSPEND"
    )
    await session.commit()
    return JSONResponse(envelope(request, _device_payload(device)))


@router.delete("/devices/{device_id}", summary="Revoke a device")
async def revoke_device(
    device_id: UUID,
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    device = await _device(session, principal.tenant_id, device_id)
    if device.user_id != principal.user_id and not principal.can("monitor:device:manage"):
        raise ApiError(403, "permission_denied", "You cannot revoke this device.")
    device.status = "REVOKED"
    device.revoked_at = _now()
    _queue_command(
        session, tenant_id=principal.tenant_id, device_id=device.id, command_type="REVOKE"
    )
    await session.commit()
    return JSONResponse(envelope(request, _device_payload(device)))


@router.post("/devices/{device_id}/wipe", summary="Request a remote wipe")
async def wipe_device(
    device_id: UUID,
    principal: DeviceManage,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    device = await _device(session, principal.tenant_id, device_id)
    device.wipe_requested_at = _now()
    _queue_command(
        session, tenant_id=principal.tenant_id, device_id=device.id, command_type="WIPE"
    )
    await session.commit()
    return JSONResponse(envelope(request, _device_payload(device)))


@router.get("/devices/{device_id}/commands", summary="Pending commands for a device")
async def list_commands(
    device_id: UUID,
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    device = await _device(session, principal.tenant_id, device_id)
    if device.user_id != principal.user_id and not principal.can("monitor:device:manage"):
        raise ApiError(403, "permission_denied", "You cannot read this device's commands.")
    rows = (
        await session.execute(
            select(DeviceCommand).where(
                DeviceCommand.tenant_id == principal.tenant_id,
                DeviceCommand.device_id == device_id,
                DeviceCommand.status == "PENDING",
            )
        )
    ).scalars()
    return JSONResponse(
        envelope(
            request,
            [
                {
                    "id": str(command.id),
                    "type": command.type,
                    "created_at": command.created_at.isoformat(),
                }
                for command in rows
            ],
        )
    )


@router.post("/devices/{device_id}/commands/{command_id}/ack", summary="Acknowledge a command")
async def ack_command(
    device_id: UUID,
    command_id: UUID,
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    device = await _device(session, principal.tenant_id, device_id)
    if device.user_id != principal.user_id and not principal.can("monitor:device:manage"):
        raise ApiError(403, "permission_denied", "You cannot acknowledge this command.")
    command = await session.get(DeviceCommand, command_id)
    if (
        command is None
        or command.tenant_id != principal.tenant_id
        or command.device_id != device_id
    ):
        raise ApiError(404, "not_found", "Command not found.")
    command.status = "ACKED"
    command.acknowledged_at = _now()
    await session.commit()
    return JSONResponse(envelope(request, {"id": str(command.id), "status": command.status}))


@router.post("/sessions/start", status_code=201, summary="Start a monitoring session")
async def start_monitoring(
    payload: SessionStart, principal: TimerPerm, request: Request, session: SessionDep
) -> JSONResponse:
    work_session = await worklog.get_session(
        request, principal.tenant_id, payload.work_session_id
    )
    if work_session is None:
        raise ApiError(404, "not_found", "Work session not found.")
    if UUID(str(work_session["user_id"])) != principal.user_id:
        raise ApiError(403, "permission_denied", "That work session belongs to another user.")
    if payload.device_id is not None:
        device = await _device(session, principal.tenant_id, payload.device_id)
        if device.user_id != principal.user_id or device.status != "ACTIVE":
            raise ApiError(403, "permission_denied", "That device is not active for you.")
    existing = (
        await session.execute(
            select(MonitoringSession).where(
                MonitoringSession.tenant_id == principal.tenant_id,
                MonitoringSession.work_session_id == payload.work_session_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return JSONResponse(envelope(request, _session_payload(existing)))

    monitor_session = MonitoringSession(
        id=new_id(),
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        work_session_id=payload.work_session_id,
        device_id=payload.device_id,
        started_at=_now(),
        state="ACTIVE",
    )
    session.add(monitor_session)
    await session.commit()
    return JSONResponse(envelope(request, _session_payload(monitor_session)), status_code=201)


@router.post("/sessions/{session_id}/heartbeat", summary="Record an activity heartbeat")
async def heartbeat(
    session_id: UUID,
    payload: Heartbeat,
    principal: TimerPerm,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    monitor_session = await _monitor_session(session, principal.tenant_id, session_id)
    if monitor_session.user_id != principal.user_id or monitor_session.state != "ACTIVE":
        raise ApiError(403, "permission_denied", "That monitoring session is not active.")
    session.add(
        ActivityHeartbeat(
            tenant_id=principal.tenant_id,
            session_id=monitor_session.id,
            user_id=principal.user_id,
            recorded_at=_now(),
            active_seconds=payload.active_seconds,
            idle_seconds=payload.idle_seconds,
            device_state=payload.device_state,
        )
    )
    await session.commit()
    totals = (
        await session.execute(
            select(
                func.coalesce(func.sum(ActivityHeartbeat.active_seconds), 0),
                func.coalesce(func.sum(ActivityHeartbeat.idle_seconds), 0),
            ).where(ActivityHeartbeat.session_id == monitor_session.id)
        )
    ).one()
    return JSONResponse(
        envelope(
            request,
            {"active_seconds": int(totals[0]), "idle_seconds": int(totals[1])},
        )
    )


@router.post("/sessions/{session_id}/stop", summary="Stop a monitoring session")
async def stop_monitoring(
    session_id: UUID,
    principal: TimerPerm,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    monitor_session = await _monitor_session(session, principal.tenant_id, session_id)
    if monitor_session.user_id != principal.user_id:
        raise ApiError(403, "permission_denied", "That monitoring session belongs to another user.")
    if monitor_session.state == "ACTIVE":
        monitor_session.state = "STOPPED"
        monitor_session.ended_at = _now()
        await session.commit()
    return JSONResponse(envelope(request, _session_payload(monitor_session)))


@router.post("/screenshots", status_code=201, summary="Upload a pending screenshot")
async def upload_screenshot(
    principal: TimerPerm,
    request: Request,
    session: SessionDep,
    session_id: Annotated[UUID, Form()],
    device_id: Annotated[UUID, Form()],
    captured_at: Annotated[datetime, Form()],
    width: Annotated[int, Form(ge=1, le=20000)],
    height: Annotated[int, Form(ge=1, le=20000)],
    display_index: Annotated[int, Form(ge=0, le=16)] = 0,
    file: UploadFile = File(...),
) -> JSONResponse:
    settings = request.app.state.settings
    device = await _device(session, principal.tenant_id, device_id)
    if device.user_id != principal.user_id or device.status != "ACTIVE":
        raise ApiError(403, "permission_denied", "That device cannot upload captures.")
    monitor_session = await _monitor_session(session, principal.tenant_id, session_id)
    if monitor_session.user_id != principal.user_id or monitor_session.state != "ACTIVE":
        raise ApiError(403, "permission_denied", "That monitoring session is not active.")
    now = _now()
    captured = captured_at if captured_at.tzinfo else captured_at.replace(tzinfo=UTC)
    if captured > now + timedelta(seconds=60) or captured < monitor_session.started_at - timedelta(
        minutes=5
    ):
        raise ApiError(422, "validation_failed", "The capture time is outside the session.")
    content_type = file.content_type or "application/octet-stream"
    if content_type not in ALLOWED_TYPES:
        raise ApiError(415, "unsupported_media_type", "That image type is not supported.")
    body = await file.read()
    validate_upload(body, content_type, max_bytes=settings.screenshot_max_bytes)
    await virus_scan(settings, body)
    content_hash = hashlib.sha256(body).hexdigest()
    existing = (
        await session.execute(
            select(Screenshot).where(
                Screenshot.tenant_id == principal.tenant_id,
                Screenshot.session_id == monitor_session.id,
                Screenshot.content_hash == content_hash,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return JSONResponse(envelope(request, _shot_payload(existing, now=now)))

    day_start = datetime.combine(now.date(), time.min, tzinfo=UTC)
    count = (
        await session.execute(
            select(func.count())
            .select_from(Screenshot)
            .where(
                Screenshot.tenant_id == principal.tenant_id,
                Screenshot.user_id == principal.user_id,
                Screenshot.captured_at >= day_start,
            )
        )
    ).scalar_one()
    if count >= settings.screenshot_daily_quota:
        raise ApiError(429, "quota_exceeded", "Daily capture quota reached.")

    screenshot_id = new_id()
    envelope_data = crypto.encrypt(body, secret=settings.monitoring_encryption_key)
    key = storage.screenshot_key(str(principal.tenant_id), str(screenshot_id))
    storage.put(settings, key, envelope_data.ciphertext)
    screenshot = Screenshot(
        id=screenshot_id,
        tenant_id=principal.tenant_id,
        session_id=monitor_session.id,
        user_id=principal.user_id,
        device_id=device.id,
        captured_at=captured,
        storage_key=key,
        kms_key_id=envelope_data.key_id,
        wrapped_key=envelope_data.wrapped_key,
        content_hash=content_hash,
        content_type=content_type,
        size_bytes=len(body),
        width=width,
        height=height,
        display_index=display_index,
        state="PENDING",
        visible_after=captured + timedelta(hours=settings.privacy_window_hours),
        retention_expires_at=captured + timedelta(days=settings.retention_days),
    )
    session.add(screenshot)
    await session.commit()
    return JSONResponse(envelope(request, _shot_payload(screenshot, now=now)), status_code=201)


@router.get("/screenshots/mine", summary="My screenshots")
async def my_screenshots(
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
    state_filter: str | None = Query(default=None, alias="state"),
    from_date: date | None = Query(default=None, alias="from"),
    to_date: date | None = Query(default=None, alias="to"),
) -> JSONResponse:
    start, end = _range(from_date, to_date)
    query = select(Screenshot).where(
        Screenshot.tenant_id == principal.tenant_id,
        Screenshot.user_id == principal.user_id,
        Screenshot.captured_at >= start,
        Screenshot.captured_at < end,
    )
    if state_filter:
        query = query.where(Screenshot.state == state_filter.upper())
    rows = (
        await session.execute(query.order_by(Screenshot.captured_at.desc()).limit(200))
    ).scalars()
    now = _now()
    return JSONResponse(
        envelope(
            request,
            [_shot_payload(row, now=now) for row in rows],
            privacy_window_hours=request.app.state.settings.privacy_window_hours,
        )
    )


@router.get("/screenshots", summary="Manager screenshot gallery")
async def manager_screenshots(
    principal: MonitorView,
    request: Request,
    session: SessionDep,
    user_id: UUID | None = Query(default=None),
    from_date: date | None = Query(default=None, alias="from"),
    to_date: date | None = Query(default=None, alias="to"),
) -> JSONResponse:
    start, end = _range(from_date, to_date)
    now = _now()
    query = select(Screenshot).where(
        Screenshot.tenant_id == principal.tenant_id,
        Screenshot.captured_at >= start,
        Screenshot.captured_at < end,
        or_(
            Screenshot.state.in_(("VISIBLE", "DELETED", "EXPIRED")),
        ),
    )
    scoped = await _scoped_user_ids(request, principal)
    if scoped is not None:
        query = query.where(Screenshot.user_id.in_(scoped))
    if user_id is not None:
        if scoped is not None and user_id not in scoped:
            raise ApiError(404, "not_found", "User not found in your scope.")
        query = query.where(Screenshot.user_id == user_id)
    rows = (
        await session.execute(query.order_by(Screenshot.captured_at.desc()).limit(200))
    ).scalars()
    return JSONResponse(
        envelope(
            request,
            [_shot_payload(row, now=now) for row in rows],
            view_audit=True,
        )
    )


@router.get("/screenshots/{screenshot_id}/content", summary="Decrypted screenshot bytes")
async def screenshot_content(
    screenshot_id: UUID,
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
) -> Response:
    screenshot = await session.get(Screenshot, screenshot_id)
    if screenshot is None or screenshot.tenant_id != principal.tenant_id:
        raise ApiError(404, "not_found", "Screenshot not found.")
    now = _now()
    is_owner = screenshot.user_id == principal.user_id
    if not is_owner:
        if not principal.can("monitor:data:view_team"):
            raise ApiError(404, "not_found", "Screenshot not found.")
        if screenshot.state != "VISIBLE":
            raise ApiError(404, "not_found", "Screenshot not found.")
        scoped = await _scoped_user_ids(request, principal)
        if scoped is not None and screenshot.user_id not in scoped:
            raise ApiError(404, "not_found", "Screenshot not found.")
    if screenshot.state in ("DELETED", "EXPIRED") or not screenshot.storage_key:
        raise ApiError(404, "not_found", "Screenshot not found.")
    settings = request.app.state.settings
    encrypted = storage.get(settings, screenshot.storage_key)
    plaintext = crypto.decrypt(
        encrypted,
        screenshot.wrapped_key or "",
        secret=settings.monitoring_encryption_key,
        key_id=screenshot.kms_key_id or "",
    )
    session.add(
        ScreenshotView(
            tenant_id=principal.tenant_id,
            screenshot_id=screenshot.id,
            viewer_id=principal.user_id,
            viewed_at=now,
            source="WEB",
        )
    )
    await session.commit()
    return Response(content=plaintext, media_type=screenshot.content_type or "image/png")


@router.delete("/screenshots/{screenshot_id}", status_code=204, summary="Delete a screenshot")
async def delete_screenshot(
    screenshot_id: UUID,
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
) -> Response:
    screenshot = await session.get(Screenshot, screenshot_id)
    if (
        screenshot is None
        or screenshot.tenant_id != principal.tenant_id
        or screenshot.user_id != principal.user_id
    ):
        raise ApiError(404, "not_found", "Screenshot not found.")
    if screenshot.state == "DELETED":
        return Response(status_code=204)
    now = _now()
    if now > screenshot.visible_after:
        raise ApiError(403, "window_closed", "The privacy window for this capture has closed.")
    settings = request.app.state.settings
    if screenshot.storage_key:
        storage.delete(settings, screenshot.storage_key)
    screenshot.storage_key = None
    screenshot.wrapped_key = None
    screenshot.state = "DELETED"
    screenshot.deleted_by_user = True
    screenshot.deleted_at = now
    screenshot.deleted_by = principal.user_id
    session.add(
        DeletionAudit(
            tenant_id=principal.tenant_id,
            screenshot_id=screenshot.id,
            user_id=principal.user_id,
            deleted_at=now,
            request_source="WEB",
            blob_confirmed_deleted=True,
            embedding_confirmed_deleted=True,
        )
    )
    enqueue(
        session,
        event_type="screenshot.deleted",
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        payload={
            "screenshot_id": str(screenshot.id),
            "user_id": str(screenshot.user_id),
            "captured_at": screenshot.captured_at.isoformat(),
        },
    )
    await session.commit()
    return Response(status_code=204)


@router.post("/screenshots/{screenshot_id}/promote", summary="Make a capture visible now")
async def promote_screenshot(
    screenshot_id: UUID,
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    screenshot = await session.get(Screenshot, screenshot_id)
    if (
        screenshot is None
        or screenshot.tenant_id != principal.tenant_id
        or screenshot.user_id != principal.user_id
    ):
        raise ApiError(404, "not_found", "Screenshot not found.")
    if screenshot.state != "PENDING":
        return JSONResponse(envelope(request, _shot_payload(screenshot, now=_now())))
    now = _now()
    screenshot.state = "VISIBLE"
    enqueue(
        session,
        event_type="screenshot.available",
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        payload={
            "screenshot_id": str(screenshot.id),
            "user_id": str(screenshot.user_id),
            "captured_at": screenshot.captured_at.isoformat(),
        },
    )
    await session.commit()
    return JSONResponse(envelope(request, _shot_payload(screenshot, now=now)))


@router.get("/sessions", summary="Monitoring sessions for managers")
async def manager_sessions(
    principal: MonitorView,
    request: Request,
    session: SessionDep,
    user_id: UUID | None = Query(default=None),
    from_date: date | None = Query(default=None, alias="from"),
    to_date: date | None = Query(default=None, alias="to"),
) -> JSONResponse:
    start, end = _range(from_date, to_date)
    query = select(MonitoringSession).where(
        MonitoringSession.tenant_id == principal.tenant_id,
        MonitoringSession.started_at >= start,
        MonitoringSession.started_at < end,
    )
    scoped = await _scoped_user_ids(request, principal)
    if scoped is not None:
        query = query.where(MonitoringSession.user_id.in_(scoped))
    if user_id is not None:
        if scoped is not None and user_id not in scoped:
            raise ApiError(404, "not_found", "User not found in your scope.")
        query = query.where(MonitoringSession.user_id == user_id)
    rows = (
        await session.execute(query.order_by(MonitoringSession.started_at.desc()).limit(200))
    ).scalars()
    return JSONResponse(envelope(request, [_session_payload(row) for row in rows]))


@router.get("/transparency", summary="My personal transparency log")
async def transparency(
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
    from_date: date | None = Query(default=None, alias="from"),
    to_date: date | None = Query(default=None, alias="to"),
) -> JSONResponse:
    start, end = _range(from_date, to_date)
    now = _now()
    captures = (
        await session.execute(
            select(Screenshot)
            .where(
                Screenshot.tenant_id == principal.tenant_id,
                Screenshot.user_id == principal.user_id,
                Screenshot.captured_at >= start,
                Screenshot.captured_at < end,
            )
            .order_by(Screenshot.captured_at.desc())
            .limit(200)
        )
    ).scalars()
    deletions = (
        await session.execute(
            select(DeletionAudit)
            .where(
                DeletionAudit.tenant_id == principal.tenant_id,
                DeletionAudit.user_id == principal.user_id,
                DeletionAudit.deleted_at >= start,
                DeletionAudit.deleted_at < end,
            )
            .order_by(DeletionAudit.deleted_at.desc())
            .limit(200)
        )
    ).scalars()
    sessions = (
        await session.execute(
            select(MonitoringSession)
            .where(
                MonitoringSession.tenant_id == principal.tenant_id,
                MonitoringSession.user_id == principal.user_id,
                MonitoringSession.started_at >= start,
                MonitoringSession.started_at < end,
            )
            .order_by(MonitoringSession.started_at.desc())
            .limit(200)
        )
    ).scalars()
    return JSONResponse(
        envelope(
            request,
            {
                "captures": [_shot_payload(row, now=now) for row in captures],
                "deletions": [
                    {
                        "screenshot_id": str(row.screenshot_id),
                        "deleted_at": row.deleted_at.isoformat(),
                        "request_source": row.request_source,
                        "blob_confirmed_deleted": row.blob_confirmed_deleted,
                        "embedding_confirmed_deleted": row.embedding_confirmed_deleted,
                    }
                    for row in deletions
                ],
                "sessions": [_session_payload(row) for row in sessions],
            },
        )
    )


@router.get("/policy", summary="Effective capture policy")
async def policy(
    principal: CurrentPrincipal, request: Request
) -> JSONResponse:
    settings = request.app.state.settings
    return JSONResponse(
        envelope(
            request,
            {
                "capture_interval_seconds": settings.capture_interval_seconds,
                "privacy_window_hours": settings.privacy_window_hours,
                "retention_days": settings.retention_days,
                "states": ["PENDING", "VISIBLE", "DELETED", "EXPIRED"],
            },
        )
    )
