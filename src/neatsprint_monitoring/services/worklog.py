"""Worklog session validation for monitoring sessions."""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID

import httpx
from fastapi import Request
from neatsprint_lib.errors import ApiError

CACHE_TTL_SECONDS = 10.0
_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}


def clear_cache() -> None:
    _cache.clear()


async def get_session(
    request: Request, tenant_id: UUID, session_id: UUID
) -> dict[str, Any] | None:
    key = (str(tenant_id), str(session_id))
    now = time.monotonic()
    cached = _cache.get(key)
    if cached is not None and cached[0] > now:
        return cached[1]
    settings = request.app.state.settings
    token = settings.service_token or settings.bootstrap_token
    if not token:
        raise ApiError(503, "dependency_unavailable", "Worklog validation is not configured.")
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            response = await client.get(
                f"{settings.worklog_internal_url}/internal/sessions/{session_id}",
                params={"tenant_id": str(tenant_id)},
                headers={"X-Service-Token": token},
            )
    except httpx.HTTPError as exc:
        raise ApiError(
            503, "dependency_unavailable", "Could not validate the work session."
        ) from exc
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise ApiError(
            503, "dependency_unavailable", "Could not validate the work session."
        )
    payload = response.json().get("data")
    if not isinstance(payload, dict):
        raise ApiError(
            503, "dependency_unavailable", "Could not validate the work session."
        )
    _cache[key] = (now + CACHE_TTL_SECONDS, payload)
    return payload
