"""S3 storage for encrypted screenshots."""

from __future__ import annotations

from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.client import Config  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from neatsprint_lib.errors import ApiError

from neatsprint_monitoring.settings import Settings


def _client(settings: Settings) -> Any:
    if not settings.s3_endpoint or not settings.s3_access_key:
        raise ApiError(503, "dependency_unavailable", "Object storage is not configured.")
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name=settings.s3_region,
        config=Config(signature_version="s3v4"),
    )


def screenshot_key(tenant_id: str, screenshot_id: str) -> str:
    return f"tenant/{tenant_id}/screenshots/{screenshot_id}.enc"


def put(settings: Settings, key: str, body: bytes) -> None:
    try:
        _client(settings).put_object(
            Bucket=settings.s3_bucket,
            Key=key,
            Body=body,
            ContentType="application/octet-stream",
        )
    except (BotoCoreError, ClientError) as exc:
        raise ApiError(503, "dependency_unavailable", "Could not store the capture.") from exc


def delete(settings: Settings, key: str) -> None:
    try:
        _client(settings).delete_object(
            Bucket=settings.s3_bucket,
            Key=key,
        )
    except (BotoCoreError, ClientError) as exc:
        raise ApiError(503, "dependency_unavailable", "Could not delete the capture.") from exc


def get(settings: Settings, key: str) -> bytes:
    try:
        response = _client(settings).get_object(
            Bucket=settings.s3_bucket,
            Key=key,
        )
        return bytes(response["Body"].read())
    except (BotoCoreError, ClientError) as exc:
        raise ApiError(404, "not_found", "Capture not found.") from exc
