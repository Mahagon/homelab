"""Minimal Alexa Smart Home v3 bridge for Home Assistant.

The function intentionally has no third-party dependencies and never logs the
incoming directive because it contains the Home Assistant OAuth access token.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
if not BASE_URL.startswith("https://"):
    raise RuntimeError("BASE_URL must use HTTPS")

HOME_ASSISTANT_ENDPOINT = f"{BASE_URL}/api/alexa/smart_home"
ORIGIN_TIMEOUT_SECONDS = 6.5
MAX_PAYLOAD_BYTES = 1024 * 1024

TLS_CONTEXT = ssl.create_default_context()
TLS_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2


def _directive(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict) or not isinstance(event.get("directive"), dict):
        raise ValueError("Missing directive")
    return event["directive"]


def _header(directive: dict[str, Any]) -> dict[str, Any]:
    header = directive.get("header")
    if not isinstance(header, dict):
        raise ValueError("Missing directive header")
    if header.get("payloadVersion") != "3":
        raise ValueError("Only Alexa Smart Home payload version 3 is supported")
    if not isinstance(header.get("namespace"), str) or not isinstance(header.get("name"), str):
        raise ValueError("Missing directive namespace or name")
    return header


def _bearer_token(directive: dict[str, Any]) -> str:
    scopes = []
    endpoint = directive.get("endpoint")
    payload = directive.get("payload")
    if isinstance(endpoint, dict):
        scopes.append(endpoint.get("scope"))
    if isinstance(payload, dict):
        scopes.append(payload.get("scope"))

    for scope in scopes:
        if not isinstance(scope, dict) or scope.get("type") != "BearerToken":
            continue
        token = scope.get("token")
        if isinstance(token, str) and token.strip():
            return token
    raise PermissionError("Missing bearer token")


def _error_response(event: Any, error_type: str, message: str) -> dict[str, Any]:
    response_header: dict[str, Any] = {
        "namespace": "Alexa",
        "name": "ErrorResponse",
        "messageId": str(uuid.uuid4()),
        "payloadVersion": "3",
    }
    response: dict[str, Any] = {
        "event": {
            "header": response_header,
            "payload": {"type": error_type, "message": message},
        }
    }

    try:
        directive = _directive(event)
        request_header = directive.get("header", {})
        correlation_token = request_header.get("correlationToken")
        if isinstance(correlation_token, str):
            response_header["correlationToken"] = correlation_token

        endpoint = directive.get("endpoint")
        if isinstance(endpoint, dict) and isinstance(endpoint.get("endpointId"), str):
            response["event"]["endpoint"] = {"endpointId": endpoint["endpointId"]}
    except ValueError:
        pass

    return response


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    started = time.monotonic()

    try:
        directive = _directive(event)
        header = _header(directive)
    except ValueError as exc:
        LOGGER.warning("Rejected malformed Alexa directive", extra={"reason": str(exc)})
        return _error_response(event, "INVALID_DIRECTIVE", "The Alexa directive is invalid.")

    namespace = header["namespace"]
    name = header["name"]
    request_id = getattr(context, "aws_request_id", "unknown")

    try:
        token = _bearer_token(directive)
    except PermissionError:
        LOGGER.warning(
            "Rejected Alexa directive without authorization",
            extra={"request_id": request_id, "namespace": namespace, "directive_name": name},
        )
        return _error_response(
            event,
            "INVALID_AUTHORIZATION_CREDENTIAL",
            "The authorization credential is missing or invalid.",
        )

    encoded_event = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded_event) > MAX_PAYLOAD_BYTES:
        LOGGER.warning(
            "Rejected oversized Alexa directive",
            extra={"request_id": request_id, "namespace": namespace, "directive_name": name},
        )
        return _error_response(event, "INVALID_DIRECTIVE", "The Alexa directive is too large.")

    request = urllib.request.Request(
        HOME_ASSISTANT_ENDPOINT,
        data=encoded_event,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "home-assistant-alexa-lambda/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=ORIGIN_TIMEOUT_SECONDS,
            context=TLS_CONTEXT,
        ) as origin_response:
            payload = origin_response.read(MAX_PAYLOAD_BYTES + 1)
            status = origin_response.status
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("Home Assistant response exceeded the maximum size")
        response = json.loads(payload.decode("utf-8"))
        if not isinstance(response, dict):
            raise ValueError("Home Assistant returned a non-object response")
    except urllib.error.HTTPError as exc:
        LOGGER.warning(
            "Home Assistant rejected Alexa directive",
            extra={
                "request_id": request_id,
                "namespace": namespace,
                "directive_name": name,
                "origin_status": exc.code,
            },
        )
        if exc.code in (401, 403):
            return _error_response(
                event,
                "INVALID_AUTHORIZATION_CREDENTIAL",
                "Home Assistant rejected the authorization credential.",
            )
        return _error_response(event, "ENDPOINT_UNREACHABLE", "Home Assistant rejected the request.")
    except (urllib.error.URLError, TimeoutError, socket.timeout):
        LOGGER.warning(
            "Home Assistant is unreachable",
            extra={"request_id": request_id, "namespace": namespace, "directive_name": name},
        )
        return _error_response(event, "ENDPOINT_UNREACHABLE", "Home Assistant is unavailable.")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        LOGGER.error(
            "Home Assistant returned an invalid response",
            extra={"request_id": request_id, "namespace": namespace, "directive_name": name},
        )
        return _error_response(event, "INTERNAL_ERROR", "Home Assistant returned an invalid response.")

    LOGGER.info(
        "Alexa directive completed",
        extra={
            "request_id": request_id,
            "namespace": namespace,
            "directive_name": name,
            "origin_status": status,
            "duration_ms": round((time.monotonic() - started) * 1000),
        },
    )
    return response
