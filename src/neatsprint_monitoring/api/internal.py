"""Internal monitoring facts for the reports backfill."""

from __future__ import annotations

import secrets
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from neatsprint_lib.db import bind_tenant, get_session
from neatsprint_lib.errors import ApiError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from neatsprint_monitoring.db.models import Screenshot

router = APIRouter(prefix="/internal", tags=["internal"])
AdminSession = Annotated[AsyncSession, Depends(get_session)]


async def _service_guard(
    request: Request, x_service_token: Annotated[str | None, Header()] = None
) -> None:
    expected = request.app.state.settings.bootstrap_token
    if not expected or not x_service_token or not secrets.compare_digest(
        x_service_token, expected
    ):
        raise ApiError(403, "permission_denied", "Invalid service token.")


ServiceDep = Annotated[None, Depends(_service_guard)]


@router.get("/screenshots", summary="Internal paginated screenshot facts")
async def internal_screenshots(
    tenant_id: UUID,
    _: ServiceDep,
    request: Request,
    session: AdminSession,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> JSONResponse:
    bind_tenant(session, tenant_id)
    rows = (
        await session.execute(
            select(Screenshot)
            .where(Screenshot.tenant_id == tenant_id)
            .order_by(Screenshot.captured_at, Screenshot.id)
            .offset(offset)
            .limit(limit)
        )
    ).scalars()
    return JSONResponse(
        {
            "data": [
                {
                    "screenshot_id": str(row.id),
                    "user_id": str(row.user_id),
                    "captured_at": row.captured_at.isoformat(),
                    "state": row.state,
                    "deleted_at": row.deleted_at.isoformat() if row.deleted_at else None,
                }
                for row in rows
            ]
        }
    )
