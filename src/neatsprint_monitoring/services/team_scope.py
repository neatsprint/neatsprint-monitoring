"""Team scope lookup used by manager monitoring."""

from __future__ import annotations

import time
from dataclasses import dataclass
from uuid import UUID

import httpx
from fastapi import Request

CACHE_TTL_SECONDS = 60.0
_cache: dict[tuple[str, str], tuple[float, Scope]] = {}


@dataclass(frozen=True, slots=True)
class Scope:
    team_ids: frozenset[UUID]
    user_ids: frozenset[UUID]


def clear_cache() -> None:
    _cache.clear()


async def scope_for_user(
    request: Request, tenant_id: UUID, user_id: UUID
) -> Scope | None:
    key = (str(tenant_id), str(user_id))
    now = time.monotonic()
    cached = _cache.get(key)
    if cached is not None and cached[0] > now:
        return cached[1]
    settings = request.app.state.settings
    token = settings.service_token or settings.bootstrap_token
    if not token:
        return None
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            response = await client.get(
                f"{settings.team_internal_url}/internal/users/{user_id}/scope",
                params={"tenant_id": str(tenant_id)},
                headers={"X-Service-Token": token},
            )
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    payload = response.json().get("data")
    if not isinstance(payload, dict):
        return None
    try:
        scope = Scope(
            team_ids=frozenset(UUID(str(item)) for item in payload.get("team_ids", [])),
            user_ids=frozenset(UUID(str(item)) for item in payload.get("user_ids", [])),
        )
    except (TypeError, ValueError):
        return None
    _cache[key] = (now + CACHE_TTL_SECONDS, scope)
    return scope
