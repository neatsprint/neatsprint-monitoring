from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from neatsprint_monitoring.api.router import _shot_payload
from neatsprint_monitoring.db.models import Screenshot
from neatsprint_monitoring.services import crypto
from neatsprint_monitoring.services.jobs import promote_available


def _screenshot(**overrides: object) -> Screenshot:
    captured = datetime(2026, 11, 24, 9, 0, tzinfo=UTC)
    values: dict[str, object] = {
        "id": uuid4(),
        "tenant_id": uuid4(),
        "session_id": uuid4(),
        "user_id": uuid4(),
        "device_id": None,
        "captured_at": captured,
        "storage_key": "tenant/1/screenshots/x.enc",
        "kms_key_id": crypto.KEY_ID,
        "wrapped_key": "key",
        "content_hash": "hash",
        "content_type": "image/png",
        "size_bytes": 10,
        "width": 100,
        "height": 100,
        "display_index": 0,
        "state": "PENDING",
        "visible_after": captured + timedelta(hours=24),
        "deleted_by_user": False,
        "deleted_at": None,
        "deleted_by": None,
        "retention_expires_at": captured + timedelta(days=30),
    }
    values.update(overrides)
    return Screenshot(**values)


def test_envelope_round_trip() -> None:
    plaintext = b"pixels"
    envelope = crypto.encrypt(plaintext, secret="secret")
    assert envelope.key_id == crypto.KEY_ID
    assert envelope.ciphertext != plaintext
    assert crypto.decrypt(
        envelope.ciphertext,
        envelope.wrapped_key,
        secret="secret",
        key_id=envelope.key_id,
    ) == plaintext


def test_envelope_rejects_wrong_key() -> None:
    envelope = crypto.encrypt(b"pixels", secret="secret")
    with pytest.raises(InvalidTag):
        crypto.decrypt(
            envelope.ciphertext,
            envelope.wrapped_key,
            secret="other",
            key_id=envelope.key_id,
        )


def test_pending_capture_is_deletable_only_inside_window() -> None:
    now = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    screenshot = _screenshot()
    payload = _shot_payload(screenshot, now=now)
    assert payload["can_delete"] is True
    assert payload["window_open"] is True
    assert payload["content_url"] is not None

    after_window = _shot_payload(
        screenshot, now=screenshot.visible_after + timedelta(seconds=1)
    )
    assert after_window["can_delete"] is False


def test_deleted_capture_hides_content() -> None:
    screenshot = _screenshot(
        state="DELETED",
        deleted_by_user=True,
        storage_key=None,
        wrapped_key=None,
        deleted_at=datetime(2026, 11, 24, 10, 0, tzinfo=UTC),
    )
    payload = _shot_payload(screenshot, now=datetime(2026, 11, 24, 11, 0, tzinfo=UTC))
    assert payload["content_url"] is None
    assert payload["can_delete"] is False
    assert payload["deleted_at"] is not None


class _FakeResult:
    def __init__(self, rows: list[Screenshot]) -> None:
        self.rows = rows

    def scalars(self) -> list[Screenshot]:
        return self.rows


class _FakeSession:
    def __init__(self, rows: list[Screenshot]) -> None:
        self.rows = rows
        self.added: list[object] = []
        self.committed = False

    async def execute(self, statement: object) -> _FakeResult:
        return _FakeResult(self.rows)

    def add(self, instance: object) -> None:
        self.added.append(instance)

    async def commit(self) -> None:
        self.committed = True


async def test_promotion_marks_pending_visible() -> None:
    now = datetime.now(tz=UTC)
    screenshot = _screenshot(
        captured_at=now - timedelta(hours=25),
        visible_after=now - timedelta(hours=1),
    )
    session = _FakeSession([screenshot])

    promoted = await promote_available(session, object())  # type: ignore[arg-type]

    assert promoted == 1
    assert screenshot.state == "VISIBLE"
    assert session.committed is True
    assert len(session.added) == 1
