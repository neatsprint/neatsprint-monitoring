"""Background privacy and retention jobs."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from neatsprint_lib.events import enqueue
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from neatsprint_monitoring.db.models import Screenshot
from neatsprint_monitoring.services import storage
from neatsprint_monitoring.settings import Settings

logger = logging.getLogger(__name__)


async def promote_available(
    session: AsyncSession, settings: Settings
) -> int:
    now = datetime.now(tz=UTC)
    rows = list(
        (
            await session.execute(
                select(Screenshot).where(
                    Screenshot.state == "PENDING",
                    Screenshot.visible_after <= now,
                    Screenshot.storage_key.is_not(None),
                )
            )
        ).scalars()
    )
    for screenshot in rows:
        screenshot.state = "VISIBLE"
        enqueue(
            session,
            event_type="screenshot.available",
            tenant_id=screenshot.tenant_id,
            actor_id=screenshot.user_id,
            payload={
                "screenshot_id": str(screenshot.id),
                "user_id": str(screenshot.user_id),
                "captured_at": screenshot.captured_at.isoformat(),
            },
        )
    await session.commit()
    return len(rows)


async def expire_retention(
    session: AsyncSession, settings: Settings
) -> int:
    now = datetime.now(tz=UTC)
    rows = list(
        (
            await session.execute(
                select(Screenshot).where(
                    Screenshot.retention_expires_at <= now,
                    Screenshot.state != "EXPIRED",
                )
            )
        ).scalars()
    )
    expired = 0
    for screenshot in rows:
        if screenshot.storage_key:
            try:
                storage.delete(settings, screenshot.storage_key)
            except Exception:  # noqa: BLE001 - retried on the next pass
                logger.exception("screenshot_retention_delete_failed")
                continue
        screenshot.storage_key = None
        screenshot.wrapped_key = None
        screenshot.state = "EXPIRED"
        screenshot.deleted_at = now
        enqueue(
            session,
            event_type="screenshot.expired",
            tenant_id=screenshot.tenant_id,
            actor_id=screenshot.user_id,
            payload={
                "screenshot_id": str(screenshot.id),
                "user_id": str(screenshot.user_id),
                "captured_at": screenshot.captured_at.isoformat(),
            },
        )
        expired += 1
    await session.commit()
    return expired


async def run_privacy_jobs(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    stop: asyncio.Event,
) -> None:
    interval = max(5, settings.job_interval_seconds)
    while not stop.is_set():
        try:
            async with session_factory() as session:
                promoted = await promote_available(session, settings)
                expired = await expire_retention(session, settings)
                if promoted or expired:
                    logger.info(
                        "privacy_jobs_ran",
                        extra={"promoted": promoted, "expired": expired},
                    )
        except Exception:  # noqa: BLE001 - the loop must survive failures
            logger.exception("privacy_jobs_failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            continue
