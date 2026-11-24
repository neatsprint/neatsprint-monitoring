from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field


class DeviceRegister(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    platform: str = Field(pattern="^(WINDOWS|MACOS|LINUX)$")
    public_key: str = Field(min_length=32, max_length=4096)


class SessionStart(BaseModel):
    work_session_id: UUID
    device_id: UUID | None = None


class Heartbeat(BaseModel):
    active_seconds: int = Field(default=0, ge=0, le=3600)
    idle_seconds: int = Field(default=0, ge=0, le=3600)
    device_state: str | None = Field(default=None, max_length=32)


class DeviceCommandRequest(BaseModel):
    type: str = Field(pattern="^(SUSPEND|REVOKE|WIPE)$")
