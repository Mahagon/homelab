#!/usr/bin/env python3
"""Audit, migrate, and password-protect Shelly devices managed by Home Assistant.

Runs from a workstation that can reach Home Assistant, the current Shelly
network, and VLAN 20. Secrets are requested interactively and are never written
to the migration state file. Uses only the Python standard library.

Examples:
    ./migrate_shelly_wifi.py audit
    ./migrate_shelly_wifi.py migrate --device-title 'Weihnachtsbaum'
    ./migrate_shelly_wifi.py protect --batch-size 5
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import fnmatch
import getpass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

DEFAULT_NTP_SERVERS = ("192.53.103.103", "192.53.103.108")
DEFAULT_STATE_PATH = (
    Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    / "shelly-vlan-migration"
    / "state.json"
)

_UNSET: Any = object()
# Shelly devices serve self-signed certificates; Home Assistant traffic carries an
# administrator token and always uses the verified context.
_INSECURE_TLS = ssl.create_default_context()
_INSECURE_TLS.check_hostname = False
_INSECURE_TLS.verify_mode = ssl.CERT_NONE
_VERIFIED_TLS = ssl.create_default_context()


class MigrationError(Exception):
    pass


@dataclasses.dataclass
class Entry:
    """A Home Assistant Shelly config entry."""

    entry_id: str
    title: str
    state: str
    host: str
    port: int = 80
    verify_ssl: bool = False


@dataclasses.dataclass
class Device:
    """A Shelly device as reported by its unauthenticated /shelly endpoint."""

    host: str
    port: int
    mac: str
    generation: int
    realm: str = ""
    model: str = ""
    protected: bool = False


@dataclasses.dataclass
class Reachability:
    entry: Entry
    device: Device | None
    error: str | None = None


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

_COLORS = {"green": "32", "yellow": "33", "cyan": "36"}


def say(message: str = "", color: str | None = None) -> None:
    if color and sys.stdout.isatty():
        message = f"\033[{_COLORS[color]}m{message}\033[0m"
    print(message, flush=True)


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr, flush=True)


def report_error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr, flush=True)


def confirm(target: str, action: str, *, dry_run: bool, assume_yes: bool) -> bool:
    """Replacement for PowerShell's ShouldProcess: dry-run, --yes, or prompt."""
    if dry_run:
        say(f"Would {action[0].lower()}{action[1:]} for '{target}'.")
        return False
    if assume_yes:
        return True
    answer = input(f"{action} for '{target}'? [y/N] ").strip().lower()
    return answer in ("y", "yes")


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #


def join_api_uri(base_uri: str, path: str) -> str:
    return f"{base_uri.rstrip('/')}/{path.lstrip('/')}"


def invoke_with_retry(
    operation: Callable[[], Any],
    description: str,
    attempts: int = 3,
    delay_seconds: float = 2,
) -> Any:
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except Exception as exc:  # noqa: BLE001 - retry any transient failure
            if attempt == attempts:
                raise
            warn(f"{description} failed (attempt {attempt}/{attempts}): {exc}. Retrying.")
            time.sleep(delay_seconds)


def read_secret(prompt: str) -> str:
    return getpass.getpass(f"{prompt}: ")


def read_confirmed_secret(
    prompt: str,
    minimum_length: int = 1,
    maximum_length: int = 1024,
    printable_ascii: bool = False,
) -> str:
    while True:
        first = getpass.getpass(f"{prompt}: ")
        second = getpass.getpass(f"{prompt} (confirm): ")
        if first != second:
            warn("The values do not match. Try again.")
            continue
        if not minimum_length <= len(first) <= maximum_length:
            warn(f"The value must contain between {minimum_length} and {maximum_length} characters.")
            continue
        if printable_ascii and not all(0x20 <= ord(char) <= 0x7E for char in first):
            warn("Use printable ASCII characters only.")
            continue
        return first


def normalize_mac_address(mac_address: str) -> str:
    normalized = re.sub(r"[^0-9A-Fa-f]", "", mac_address).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", normalized):
        raise MigrationError(f"Invalid MAC address '{mac_address}'.")
    return normalized


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_cidr_hosts(cidr: str) -> list[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise MigrationError(f"Invalid CIDR '{cidr}'.") from exc
    if network.version != 4:
        raise MigrationError("Only IPv4 CIDRs are supported.")
    if not 22 <= network.prefixlen <= 30:
        raise MigrationError("The target CIDR must contain between 2 and 1022 usable IPv4 hosts (/30 through /22).")
    return [str(address) for address in network.hosts()]


def is_ipv4_address_in_cidr(address: str, cidr: str) -> bool:
    return address in get_cidr_hosts(cidr)


def is_shelly_target_placement(device: Device, current_ssid: str, target_ssid: str, target_subnet: str) -> bool:
    return current_ssid == target_ssid and is_ipv4_address_in_cidr(device.host, target_subnet)


# --------------------------------------------------------------------------- #
# Low-level HTTP (TLS verification is disabled: devices use self-signed certs)
# --------------------------------------------------------------------------- #


class _NoRaiseHandler(urllib.request.HTTPDefaultErrorHandler):
    def http_error_default(self, req, fp, code, msg, hdrs):  # noqa: ANN001
        return fp


_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_INSECURE_TLS),
    _NoRaiseHandler(),
)
_VERIFIED_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_VERIFIED_TLS),
    _NoRaiseHandler(),
)


@dataclasses.dataclass
class HttpResponse:
    status: int
    headers: Any
    body: bytes
    url: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 30,
    verify_tls: bool = False,
) -> HttpResponse:
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    opener = _VERIFIED_OPENER if verify_tls else _OPENER
    try:
        with opener.open(request, timeout=timeout) as response:
            return HttpResponse(response.status, response.headers, response.read(), response.geturl())
    except urllib.error.URLError as exc:
        raise MigrationError(f"{method} {url} failed: {exc.reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise MigrationError(f"{method} {url} failed: {exc}") from exc


def _parse_json(text: str) -> Any:
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


# --------------------------------------------------------------------------- #
# Home Assistant REST API
# --------------------------------------------------------------------------- #


def ha_request(ha_url: str, token: str, method: str, path: str, body: Any = _UNSET) -> Any:
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not _UNSET:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    response = http_request(
        method, join_api_uri(ha_url, path), headers=headers, body=data, timeout=30, verify_tls=True
    )
    if not response.ok:
        raise MigrationError(f"Home Assistant {method} {path} failed with HTTP {response.status}: {response.text()}")
    return _parse_json(response.text())


def get_ha_entries(ha_url: str, token: str) -> list[dict]:
    response = ha_request(ha_url, token, "GET", "/api/config/config_entries/entry?domain=shelly")
    if isinstance(response, dict) and response.get("entries") is not None:
        response = response["entries"]
    if not isinstance(response, list):
        raise MigrationError("Home Assistant returned an unexpected config-entry payload.")
    for entry in response:
        entry_id = entry.get("entry_id") if isinstance(entry, dict) else None
        if not isinstance(entry_id, str) or not entry_id.strip():
            raise MigrationError("Home Assistant returned a Shelly config-entry item without a scalar entry_id.")
    return response


def get_flow_schema_default(flow: dict, name: str, fallback: Any = None) -> Any:
    for field in flow.get("data_schema") or []:
        if str(field.get("name")) == name:
            default = field.get("default")
            return fallback if default is None else default
    return fallback


def start_ha_entry_flow(ha_url: str, token: str, entry_id: str) -> dict:
    return ha_request(
        ha_url, token, "POST", "/api/config/config_entries/flow", {"handler": "shelly", "entry_id": entry_id}
    )


def stop_ha_entry_flow(ha_url: str, token: str, flow_id: str) -> None:
    ha_request(ha_url, token, "DELETE", f"/api/config/config_entries/flow/{flow_id}")


def get_ha_shelly_inventory(ha_url: str, token: str) -> list[Entry]:
    inventory = []
    for entry in get_ha_entries(ha_url, token):
        entry_id = entry["entry_id"]
        title = entry.get("title", "")
        flow = start_ha_entry_flow(ha_url, token, entry_id)
        try:
            if flow.get("type") != "form" or flow.get("step_id") != "reconfigure":
                raise MigrationError(f"Home Assistant did not return the expected Shelly reconfigure form for '{title}'.")
            host = get_flow_schema_default(flow, "host")
            if not str(host or "").strip():
                raise MigrationError(f"The Shelly reconfigure form for '{title}' did not contain a host.")
            inventory.append(
                Entry(
                    entry_id=entry_id,
                    title=str(title),
                    state=str(entry.get("state", "")),
                    host=str(host),
                    port=int(get_flow_schema_default(flow, "port", 80)),
                    verify_ssl=bool(get_flow_schema_default(flow, "verify_ssl", False)),
                )
            )
        finally:
            stop_ha_entry_flow(ha_url, token, flow["flow_id"])
    return inventory


def set_ha_shelly_address(
    ha_url: str, token: str, entry_id: str, host: str, port: int, verify_ssl: bool = False
) -> None:
    flow = start_ha_entry_flow(ha_url, token, entry_id)
    try:
        result = ha_request(
            ha_url,
            token,
            "POST",
            f"/api/config/config_entries/flow/{flow['flow_id']}",
            {"host": host, "port": port, "verify_ssl": verify_ssl},
        )
        result_type = result.get("type")
        reason = result.get("reason")
        if result_type != "abort" or reason not in ("reconfigure_successful", "already_configured"):
            raise MigrationError(
                "Home Assistant rejected the Shelly address update: "
                f"type={result_type}, reason={reason}, errors={json.dumps(result.get('errors'))}"
            )
    finally:
        if flow.get("flow_id"):
            try:
                stop_ha_entry_flow(ha_url, token, flow["flow_id"])
            except MigrationError:
                pass  # A successful flow removes itself.


def reload_ha_entry(ha_url: str, token: str, entry_id: str) -> None:
    ha_request(ha_url, token, "POST", f"/api/config/config_entries/entry/{entry_id}/reload", {})


def wait_ha_entry_loaded(ha_url: str, token: str, entry_id: str, timeout_seconds: float = 45) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        entry = next((e for e in get_ha_entries(ha_url, token) if e["entry_id"] == entry_id), None)
        if entry and entry.get("state") == "loaded":
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(2)


# --------------------------------------------------------------------------- #
# Minimal WebSocket client (RFC 6455) for the Home Assistant reauth flow
# --------------------------------------------------------------------------- #


class WebSocketClient:
    def __init__(self, url: str, timeout: float = 15) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("ws", "wss"):
            raise MigrationError(f"Home Assistant WebSocket URL must use ws:// or wss://: {url}")
        self._url = url
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        try:
            raw = socket.create_connection((parsed.hostname, port), timeout=timeout)
            self._sock = _VERIFIED_TLS.wrap_socket(raw, server_hostname=parsed.hostname) if parsed.scheme == "wss" else raw
        except OSError as exc:
            raise MigrationError(f"Unable to connect to the Home Assistant WebSocket at '{url}': {exc}") from exc
        self._buffer = b""
        self._handshake(parsed)

    def _handshake(self, parsed: urllib.parse.ParseResult) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(request.encode())
        while b"\r\n\r\n" not in self._buffer:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise MigrationError("WebSocket handshake failed: connection closed.")
            self._buffer += chunk
        head, _, self._buffer = self._buffer.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        if " 101 " not in lines[0] + " ":
            raise MigrationError(f"WebSocket handshake failed: {lines[0]}")
        headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])}
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        if headers.get("sec-websocket-accept") != expected:
            raise MigrationError("WebSocket handshake failed: bad Sec-WebSocket-Accept.")

    def _read_exact(self, count: int) -> bytes:
        while len(self._buffer) < count:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise MigrationError("Home Assistant closed the WebSocket connection.")
            self._buffer += chunk
        data, self._buffer = self._buffer[:count], self._buffer[count:]
        return data

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytes([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header += bytes([0x80 | length])
        elif length < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", length)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", length)
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        self._sock.sendall(header + mask + masked)

    def send_json(self, value: Any) -> None:
        self._send_frame(0x1, json.dumps(value).encode("utf-8"))

    def receive_json(self) -> Any:
        message = b""
        while True:
            first, second = self._read_exact(2)
            opcode, final = first & 0x0F, bool(first & 0x80)
            length = second & 0x7F
            if length == 126:
                (length,) = struct.unpack(">H", self._read_exact(2))
            elif length == 127:
                (length,) = struct.unpack(">Q", self._read_exact(8))
            mask = self._read_exact(4) if second & 0x80 else None
            payload = self._read_exact(length)
            if mask:
                payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
            if opcode == 0x8:
                raise MigrationError("Home Assistant closed the WebSocket connection.")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            message += payload
            if final:
                return json.loads(message.decode("utf-8"))

    def close(self) -> None:
        try:
            self._send_frame(0x8, struct.pack(">H", 1000))
        except OSError:
            pass
        finally:
            self._sock.close()


def ha_websocket_command(ws_url: str, token: str, command: dict) -> Any:
    client = WebSocketClient(ws_url)
    try:
        hello = client.receive_json()
        if hello.get("type") != "auth_required":
            raise MigrationError(f"Unexpected Home Assistant WebSocket greeting '{hello.get('type')}'.")
        client.send_json({"type": "auth", "access_token": token})
        if client.receive_json().get("type") != "auth_ok":
            raise MigrationError("Home Assistant rejected the WebSocket access token.")
        client.send_json({**command, "id": 1})
        while True:
            response = client.receive_json()
            if response.get("id") == 1:
                break
        if not response.get("success"):
            raise MigrationError(f"Home Assistant WebSocket command '{command.get('type')}' failed.")
        return response.get("result")
    finally:
        client.close()


def wait_ha_reauth_flow(ws_url: str, token: str, entry_id: str, timeout_seconds: float = 45) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while True:
        flows = ha_websocket_command(ws_url, token, {"type": "config_entries/flow/progress"}) or []
        for flow in flows:
            context = flow.get("context") or {}
            if flow.get("handler") == "shelly" and context.get("source") == "reauth" and context.get("entry_id") == entry_id:
                return flow
        if time.monotonic() >= deadline:
            raise MigrationError(f"Home Assistant did not create a Shelly reauthentication flow within {timeout_seconds:g} seconds.")
        time.sleep(2)


def complete_ha_reauth(ha_url: str, ws_url: str, token: str, entry_id: str, generation: int, password: str) -> None:
    reload_ha_entry(ha_url, token, entry_id)
    flow = wait_ha_reauth_flow(ws_url, token, entry_id)
    body = {"password": password}
    if generation == 1:
        body["username"] = "admin"
    result = ha_request(ha_url, token, "POST", f"/api/config/config_entries/flow/{flow['flow_id']}", body)
    result_type, reason = result.get("type"), result.get("reason")
    if result_type != "abort" or reason not in ("reauth_successful", "already_configured"):
        raise MigrationError(f"Home Assistant Shelly reauthentication failed: type={result_type}, reason={reason}.")


# --------------------------------------------------------------------------- #
# Shelly HTTP / RPC
# --------------------------------------------------------------------------- #


def shelly_base_uri(host: str, port: int) -> str:
    scheme = "https" if port == 443 else "http"
    if port in (80, 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _digest_header(challenge: str, username: str, password: str, method: str, uri: str) -> str:
    params = {key: quoted or bare for key, quoted, bare in re.findall(r'(\w+)=(?:"([^"]*)"|([^\s,]+))', challenge)}
    algorithm = params.get("algorithm", "MD5").upper()
    hasher = {"SHA-256": hashlib.sha256, "MD5": hashlib.md5}.get(algorithm)
    if hasher is None:
        raise MigrationError(f"Unsupported Digest algorithm '{algorithm}'.")

    def digest(value: str) -> str:
        return hasher(value.encode("utf-8")).hexdigest()

    realm, nonce = params["realm"], params["nonce"]
    cnonce, nc = secrets.token_hex(8), "00000001"
    ha1 = digest(f"{username}:{realm}:{password}")
    ha2 = digest(f"{method}:{uri}")
    response = digest(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
    fields = [
        f'username="{username}"', f'realm="{realm}"', f'nonce="{nonce}"', f'uri="{uri}"',
        f"algorithm={algorithm}", "qop=auth", f"nc={nc}", f'cnonce="{cnonce}"', f'response="{response}"',
    ]
    if "opaque" in params:
        fields.append(f'opaque="{params["opaque"]}"')
    return "Digest " + ", ".join(fields)


def shelly_digest_json_request(url: str, method: str, body: Any, password: str, timeout: float = 8) -> Any:
    """RFC 7616 challenge/response, as used by Gen2+ devices."""
    payload = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    response = http_request(method, url, headers=headers, body=payload, timeout=timeout)
    if response.status == 401:
        challenge = response.headers.get("WWW-Authenticate", "")
        if not challenge.lower().startswith("digest"):
            raise MigrationError(f"Shelly request to {url} failed with HTTP 401 without a Digest challenge.")
        uri = urllib.parse.urlparse(url).path or "/"
        headers["Authorization"] = _digest_header(challenge, "admin", password, method, uri)
        response = http_request(method, url, headers=headers, body=payload, timeout=timeout)
    if not response.ok:
        raise MigrationError(f"Shelly request to {url} failed with HTTP {response.status}: {response.text()}")
    return _parse_json(response.text())


def shelly_request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: Any = _UNSET,
    authentication: str = "none",
    password: str | None = None,
    body_type: str = "json",
    timeout: float = 8,
) -> Any:
    url = join_api_uri(shelly_base_uri(host, port), path)
    if authentication == "digest":
        if body_type != "json" or body is _UNSET:
            raise MigrationError("Shelly Digest requests require a JSON body.")
        if not password:
            raise MigrationError("A password is required for an authenticated Shelly request.")
        return shelly_digest_json_request(url, method, body, password, timeout)

    headers: dict[str, str] = {}
    data = None
    if authentication == "basic":
        if not password:
            raise MigrationError("A password is required for an authenticated Shelly request.")
        headers["Authorization"] = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()
    if body is not _UNSET:
        if body_type == "json":
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(body).encode("utf-8")
    response = http_request(method, url, headers=headers, body=data, timeout=timeout)
    if not response.ok:
        raise MigrationError(f"Shelly request to {url} failed with HTTP {response.status}: {response.text()}")
    return _parse_json(response.text())


def _identity_from_info(host: str, port: int, info: dict) -> Device:
    generation = int(info["gen"]) if info.get("gen") is not None else 1
    return Device(
        host=host,
        port=port,
        mac=normalize_mac_address(str(info.get("mac", ""))),
        generation=generation,
        realm=str(info.get("id", "")) if generation > 1 else str(info.get("hostname", "")),
        model=str(info.get("model") or info.get("type") or ""),
        protected=bool(info.get("auth_en") or info.get("auth")),
    )


def get_shelly_identity(host: str, port: int) -> Device:
    info = shelly_request(host, port, "GET", "/shelly", timeout=5)
    if not isinstance(info, dict):
        raise MigrationError(f"{host}:{port} did not return Shelly device information.")
    return _identity_from_info(host, port, info)


def _gen1_auth(device: Device) -> str:
    return "basic" if device.protected else "none"


def shelly_rpc(device: Device, method: str, params: dict | None = None, password: str | None = None) -> Any:
    response = shelly_request(
        device.host,
        device.port,
        "POST",
        "/rpc",
        {"id": 1, "method": method, "params": params or {}},
        authentication="digest" if device.protected else "none",
        password=password,
    )
    if not isinstance(response, dict):
        return response
    error = response.get("error")
    if error:
        raise MigrationError(
            f"Shelly RPC '{method}' failed: code={error.get('code')}, message={error.get('message', 'Unknown RPC error')}"
        )
    if response.get("result") is not None:
        return response["result"]
    if response.get("params") is not None:
        return response["params"]
    return response


def get_shelly_settings(device: Device, password: str | None = None) -> dict:
    if device.generation == 1:
        return shelly_request(device.host, device.port, "GET", "/settings", authentication=_gen1_auth(device), password=password)
    return {
        "Wifi": shelly_rpc(device, "Wifi.GetConfig", password=password),
        "Sys": shelly_rpc(device, "Sys.GetConfig", password=password),
        "Cloud": shelly_rpc(device, "Cloud.GetConfig", password=password),
    }


def get_shelly_primary_ssid(device: Device, password: str | None = None) -> str:
    settings = get_shelly_settings(device, password)
    if device.generation == 1:
        primary = (settings or {}).get("wifi_sta") or {}
    else:
        primary = ((settings or {}).get("Wifi") or {}).get("sta") or {}
    ssid = str(primary.get("ssid") or "")
    if not ssid.strip():
        raise MigrationError("The Shelly did not report its current primary WLAN SSID.")
    return ssid


def _gen1_post(device: Device, path: str, form: dict, password: str | None) -> Any:
    return shelly_request(
        device.host, device.port, "POST", path, form,
        authentication=_gen1_auth(device), password=password, body_type="form",
    )


def set_shelly_fallback_wifi(device: Device, ssid: str, wifi_password: str, password: str | None = None) -> None:
    if device.generation == 1:
        _gen1_post(device, "/settings/sta1", {"enabled": 1, "ssid": ssid, "key": wifi_password, "ipv4_method": "dhcp"}, password)
        config = shelly_request(
            device.host, device.port, "GET", "/settings/sta1", authentication=_gen1_auth(device), password=password
        )
        if not config.get("enabled") or config.get("ssid") != ssid:
            raise MigrationError("The Gen1 fallback Wi-Fi configuration did not pass read-back validation.")
        return

    shelly_rpc(
        device,
        "Wifi.SetConfig",
        {"config": {"sta1": {"enable": True, "ssid": ssid, "pass": wifi_password, "ipv4mode": "dhcp"}}},
        password,
    )
    config = shelly_rpc(device, "Wifi.GetConfig", password=password)
    sta1 = config.get("sta1")
    if not sta1 or not sta1.get("enable") or sta1.get("ssid") != ssid:
        raise MigrationError("The Gen2+ fallback Wi-Fi configuration did not pass read-back validation.")


def set_shelly_primary_wifi(device: Device, ssid: str, wifi_password: str, password: str | None = None) -> None:
    if device.generation == 1:
        _gen1_post(device, "/settings/sta", {"enabled": 1, "ssid": ssid, "key": wifi_password, "ipv4_method": "dhcp"}, password)
        return
    shelly_rpc(
        device,
        "Wifi.SetConfig",
        {"config": {"sta": {"enable": True, "ssid": ssid, "pass": wifi_password, "ipv4mode": "dhcp"}}},
        password,
    )


def disable_shelly_fallback_wifi(device: Device, password: str | None = None) -> None:
    if device.generation == 1:
        _gen1_post(device, "/settings/sta1", {"enabled": 0}, password)
        return
    shelly_rpc(device, "Wifi.SetConfig", {"config": {"sta1": {"enable": False}}}, password)


def set_shelly_coiot(device: Device, peer: str, password: str | None = None) -> None:
    if device.generation != 1:
        return
    _gen1_post(device, "/settings", {"coiot_enable": 1, "coiot_peer": peer}, password)


def disable_shelly_cloud(device: Device, password: str | None = None) -> None:
    if device.generation == 1:
        _gen1_post(device, "/settings/cloud", {"enabled": 0}, password)
        return
    shelly_rpc(device, "Cloud.SetConfig", {"config": {"enable": False}}, password)


def is_shelly_time_synchronized(device: Device, password: str | None = None) -> bool:
    now = int(time.time())
    if device.generation == 1:
        status = shelly_request(device.host, device.port, "GET", "/status", authentication=_gen1_auth(device), password=password)
    else:
        status = shelly_rpc(device, "Sys.GetStatus", password=password)
    unix_time = (status or {}).get("unixtime")
    return bool(unix_time) and abs(int(unix_time) - now) < 180


def set_shelly_ntp(device: Device, servers: list[str] | tuple[str, ...], password: str | None = None) -> str | None:
    for server in servers:
        configured = False
        for attempt in range(1, 4):
            try:
                if device.generation == 1:
                    _gen1_post(device, "/settings", {"sntp_server": server}, password)
                else:
                    shelly_rpc(device, "Sys.SetConfig", {"config": {"sntp": {"server": server}}}, password)
                configured = True
                break
            except MigrationError:
                if attempt < 3:
                    time.sleep(2)
        if not configured:
            continue
        for _ in range(5):
            time.sleep(3)
            try:
                if is_shelly_time_synchronized(device, password):
                    return server
            except MigrationError:
                pass
    return None


def enable_shelly_authentication(device: Device, password: str) -> Device:
    if device.generation == 1:
        shelly_request(
            device.host, device.port, "POST", "/settings/login",
            {"enabled": 1, "unprotected": 0, "username": "admin", "password": password}, body_type="form",
        )
    else:
        if not device.realm.strip():
            raise MigrationError("The Gen2+ Shelly did not report an authentication realm.")
        ha1 = sha256_hex(f"admin:{device.realm}:{password}")
        shelly_rpc(device, "Shelly.SetAuth", {"user": "admin", "realm": device.realm, "ha1": ha1})

    protected = get_shelly_identity(device.host, device.port)
    if not protected.protected:
        raise MigrationError("The Shelly did not report authentication as enabled.")
    get_shelly_settings(protected, password)
    return protected


def disable_shelly_authentication(device: Device, password: str) -> None:
    if device.generation == 1:
        shelly_request(
            device.host, device.port, "POST", "/settings/login", {"enabled": 0},
            authentication="basic", password=password, body_type="form",
        )
        return
    shelly_rpc(device, "Shelly.SetAuth", {"user": "admin", "realm": device.realm, "ha1": None}, password)


def protect_shelly_and_home_assistant(
    device: Device, entry: Entry, ha_url: str, ws_url: str, token: str, password: str
) -> Device:
    enabled_here = not device.protected
    if device.protected:
        get_shelly_settings(device, password)
        if wait_ha_entry_loaded(ha_url, token, entry.entry_id, timeout_seconds=5):
            return device
    else:
        device = enable_shelly_authentication(device, password)

    try:
        complete_ha_reauth(ha_url, ws_url, token, entry.entry_id, device.generation, password)
        if not wait_ha_entry_loaded(ha_url, token, entry.entry_id):
            raise MigrationError("Home Assistant did not return the Shelly entry to loaded state.")
        return device
    except Exception:
        if enabled_here:
            warn(f"Home Assistant reauthentication failed for '{entry.title}'; disabling the authentication enabled by this run.")
            disable_shelly_authentication(device, password)
        else:
            warn(f"Home Assistant reauthentication failed for '{entry.title}'. Existing device authentication was left enabled.")
        reload_ha_entry(ha_url, token, entry.entry_id)
        raise


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def _probe_shelly(host: str) -> Device | None:
    try:
        response = http_request("GET", f"http://{host}/shelly", timeout=2)
        if not response.ok:
            return None
        info = json.loads(response.text())
        parsed = urllib.parse.urlparse(response.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return _identity_from_info(host, port, info)
    except (MigrationError, ValueError, AttributeError, TypeError):
        return None


def find_shelly_devices_in_subnet(cidr: str) -> list[Device]:
    with ThreadPoolExecutor(max_workers=32) as pool:
        return [device for device in pool.map(_probe_shelly, get_cidr_hosts(cidr)) if device]


def wait_for_target_devices(devices: list[Device], target_subnet: str, timeout_seconds: float) -> dict[str, Device]:
    wanted = {device.mac for device in devices}
    found: dict[str, Device] = {}
    deadline = time.monotonic() + timeout_seconds
    while True:
        for candidate in find_shelly_devices_in_subnet(target_subnet):
            if candidate.mac in wanted:
                found[candidate.mac] = candidate
        if len(found) == len(wanted) or time.monotonic() >= deadline:
            return found
        time.sleep(5)


def wait_shelly_identity(host: str, port: int, expected_mac: str, timeout_seconds: float = 45) -> Device:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            identity = get_shelly_identity(host, port)
            if identity.mac == expected_mac:
                return identity
        except MigrationError:
            pass
        if time.monotonic() >= deadline:
            raise MigrationError(f"Shelly {expected_mac} did not reconnect at {host}:{port}.")
        time.sleep(2)


# --------------------------------------------------------------------------- #
# Migration state and inventory selection
# --------------------------------------------------------------------------- #


def read_migration_state(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "targetSsid": None, "updatedAt": None, "devices": []}
    return json.loads(path.read_text(encoding="utf-8"))


def write_migration_state(state: dict, path: Path) -> None:
    state["updatedAt"] = datetime.now(timezone.utc).isoformat()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=path.name, suffix=".tmp", delete=False) as handle:
        json.dump(state, handle, indent=2)
        temporary = handle.name
    os.replace(temporary, path)


def state_record(state: dict, entry_id: str) -> dict | None:
    return next((record for record in state["devices"] if record.get("entryId") == entry_id), None)


def set_migration_checkpoint(
    state: dict,
    entry: Entry,
    device: Device,
    phase: str,
    new_ip: str | None = None,
    new_port: int | None = None,
    old_ssid: Any = _UNSET,
    error: str | None = None,
) -> None:
    existing = state_record(state, entry.entry_id) or {}
    record = {
        "entryId": entry.entry_id,
        "title": entry.title,
        "mac": device.mac,
        "generation": device.generation,
        "oldIp": existing.get("oldIp") or entry.host,
        "oldSsid": existing.get("oldSsid") if old_ssid is _UNSET else old_ssid,
        "newIp": new_ip,
        "newPort": new_port,
        "phase": phase,
        "error": error,
    }
    state["devices"] = [r for r in state["devices"] if r.get("entryId") != entry.entry_id] + [record]


def resolve_inventory_from_state(inventory: list[Entry], state: dict) -> list[Entry]:
    for entry in inventory:
        record = state_record(state, entry.entry_id)
        if record and record.get("newIp") and record.get("phase") in ("discovered", "finalize_failed"):
            entry.host = str(record["newIp"])
            if record.get("newPort"):
                entry.port = int(record["newPort"])
    return inventory


def select_inventory_entries(inventory: list[Entry], device_titles: list[str] | None = None, limit: int = 0) -> list[Entry]:
    selected = sorted(inventory, key=lambda entry: entry.title.lower())
    if device_titles:
        patterns = [pattern.lower() for pattern in device_titles]
        selected = [e for e in selected if any(fnmatch.fnmatchcase(e.title.lower(), p) for p in patterns)]
    return selected[:limit] if limit > 0 else selected


def get_reachable_inventory(inventory: list[Entry]) -> list[Reachability]:
    result = []
    for entry in inventory:
        try:
            result.append(Reachability(entry, get_shelly_identity(entry.host, entry.port)))
        except MigrationError as exc:
            result.append(Reachability(entry, None, str(exc)))
    return result


def print_table(headers: list[str], rows: list[list[Any]]) -> None:
    table = [headers] + [[str(cell) for cell in row] for row in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(headers))]
    for index, row in enumerate(table):
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
        if index == 0:
            print("  ".join("-" * w for w in widths))


def show_audit(reachability: list[Reachability]) -> None:
    print_table(
        ["Title", "Host", "Generation", "Protected", "HAState", "Reachable", "Error"],
        [
            [
                r.entry.title,
                f"{r.entry.host}:{r.entry.port}",
                f"Gen{r.device.generation}" if r.device else "-",
                r.device.protected if r.device else "-",
                r.entry.state,
                bool(r.device),
                r.error or "",
            ]
            for r in reachability
        ],
    )


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class Options:
    mode: str = "audit"
    home_assistant_url: str = ""
    home_assistant_ip: str = "192.168.178.10"
    home_assistant_websocket_url: str = ""
    target_subnet: str = "192.168.20.0/24"
    ntp_servers: list[str] = dataclasses.field(default_factory=lambda: list(DEFAULT_NTP_SERVERS))
    batch_size: int = 5
    device_titles: list[str] = dataclasses.field(default_factory=list)
    discovery_timeout: int = 300
    state_path: Path = DEFAULT_STATE_PATH
    dry_run: bool = False
    assume_yes: bool = False

    def confirm(self, target: str, action: str) -> bool:
        return confirm(target, action, dry_run=self.dry_run, assume_yes=self.assume_yes)


def run_verify(opts: Options, token: str, inventory: list[Entry], device_password: str) -> None:
    current = {e["entry_id"]: e for e in get_ha_entries(opts.home_assistant_url, token)}
    rows = []
    for item in get_reachable_inventory(inventory):
        authenticated = False
        if item.device:
            try:
                get_shelly_settings(item.device, device_password)
                authenticated = True
            except MigrationError:
                pass
        current_entry = current.get(item.entry.entry_id)
        rows.append(
            [
                item.entry.title,
                item.device.host if item.device else item.entry.host,
                item.device.protected if item.device else "-",
                authenticated,
                current_entry.get("state", "unknown") if current_entry else "missing",
                bool(item.device),
            ]
        )
    print_table(["Title", "Host", "Protected", "Authenticated", "HAState", "Reachable"], rows)


def run_protect(opts: Options, token: str, inventory: list[Entry], device_password: str) -> None:
    reachability = get_reachable_inventory(inventory)
    for item in reachability:
        if not item.device:
            warn(f"Skipping '{item.entry.title}': {item.error}")
    selected = [
        r for r in reachability if r.device and (not r.device.protected or r.entry.state != "loaded")
    ][: opts.batch_size]
    if not selected:
        say("No reachable Shelly devices still require protection or Home Assistant reauthentication.", "yellow")
        return
    for item in selected:
        if not opts.confirm(item.entry.title, "Enable Shelly authentication and update Home Assistant credentials"):
            continue
        try:
            protect_shelly_and_home_assistant(
                item.device, item.entry, opts.home_assistant_url, opts.home_assistant_websocket_url, token, device_password
            )
            say(f"Protected '{item.entry.title}' and updated Home Assistant.", "green")
        except Exception as exc:  # noqa: BLE001
            report_error(f"{item.entry.title}: {exc}")


def run_rollback(opts: Options, inventory: list[Entry], state: dict, device_password: str) -> None:
    records = [r for r in state["devices"] if r.get("phase") in ("staged", "transitioning", "transition_failed")]
    old_wifi_password = None
    if any(r.get("oldSsid") for r in records):
        old_wifi_password = read_confirmed_secret("Old WLAN password for rollback", 8, 63, True)
    for record in records:
        entry = next((e for e in inventory if e.entry_id == record["entryId"]), None)
        if not entry:
            continue
        device = None
        hosts = list(dict.fromkeys(h for h in (record.get("newIp"), record.get("oldIp")) if h))
        ports = list(dict.fromkeys(p for p in (record.get("newPort"), 443, 80) if p))
        for host in hosts:
            for port in ports:
                try:
                    candidate = get_shelly_identity(host, port)
                except MigrationError:
                    continue
                if candidate.mac == record["mac"]:
                    device = candidate
                    break
            if device:
                break
        if not device:
            warn(f"Could not locate staged device '{record['title']}' on either subnet.")
            continue
        old_ssid = record.get("oldSsid")
        if not opts.confirm(record["title"], "Restore the old primary WLAN and remove the staged fallback"):
            continue
        if old_ssid:
            set_shelly_primary_wifi(device, old_ssid, old_wifi_password, device_password)
            device = wait_shelly_identity(record["oldIp"], device.port, device.mac, 60)
        disable_shelly_fallback_wifi(device, device_password)
        set_migration_checkpoint(state, entry, device, "rolled_back", old_ssid=old_ssid)
        write_migration_state(state, opts.state_path)
        say(f"Restored the old WLAN for '{record['title']}'.", "green")


def run_migrate(opts: Options, token: str, inventory: list[Entry], state: dict, device_password: str) -> None:
    ssid = input("Target VLAN WLAN SSID: ")
    if not ssid.strip() or len(ssid) > 32:
        raise MigrationError("The target SSID must contain between 1 and 32 characters.")
    wifi_password = read_confirmed_secret("Target VLAN WLAN password", 8, 63, True)

    reachability = get_reachable_inventory(inventory)
    reachable = [r for r in reachability if r.device]

    stale = []
    for r in reachability:
        if r.device:
            continue
        record = state_record(state, r.entry.entry_id)
        if record and record.get("mac") and record.get("phase") != "complete":
            stale.append((r, record))
    if stale:
        say(f"Scanning {opts.target_subnet} for checkpointed Shellys whose Home Assistant address is stale...", "cyan")
        scan = find_shelly_devices_in_subnet(opts.target_subnet)
        for r, record in stale:
            device = next((d for d in scan if d.mac == record["mac"]), None)
            if device:
                r.entry.host, r.entry.port = device.host, device.port
                reachable.append(Reachability(r.entry, device))
                say(f"Recovered '{r.entry.title}' by MAC at {device.host}.", "cyan")

    completed = {r["entryId"] for r in state["devices"] if r.get("phase") == "complete"}
    selected = [r for r in reachable if r.entry.entry_id not in completed][: opts.batch_size]
    if not selected:
        say("No reachable, incomplete Shelly devices matched this run.", "yellow")
        return

    if opts.dry_run:
        for r in selected:
            say(f"Would hand off, verify, and protect '{r.entry.title}' ({r.entry.host}).")
        return

    current_ssids: dict[str, str | None] = {}
    for r in selected:
        try:
            current_ssids[r.entry.entry_id] = get_shelly_primary_ssid(r.device, device_password)
        except MigrationError:
            current_ssids[r.entry.entry_id] = None

    def is_resume(item: Reachability) -> bool:
        record = state_record(state, item.entry.entry_id) or {}
        return bool(record.get("newIp")) and record.get("phase") in ("discovered", "finalize_failed") and item.device.host == record["newIp"]

    def is_adoptable(item: Reachability) -> bool:
        current = current_ssids[item.entry.entry_id]
        return bool(current) and is_shelly_target_placement(item.device, current, ssid, opts.target_subnet)

    old_wifi_password = None
    if any(not (is_resume(r) or is_adoptable(r)) for r in selected):
        old_wifi_password = read_confirmed_secret("Current/old WLAN password (used only as per-device fallback)", 8, 63, True)

    staged: list[Reachability] = []
    fresh_staged: list[Reachability] = []
    target_devices: dict[str, Device] = {}

    for item in selected:
        entry, title = item.entry, item.entry.title
        record = state_record(state, entry.entry_id) or {}
        if is_resume(item):
            if not opts.confirm(title, f"Resume VLAN finalization at {record['newIp']} and synchronize Home Assistant credentials"):
                continue
            staged.append(item)
            target_devices[item.device.mac] = item.device
            say(f"Resuming '{title}' at {record['newIp']}; WLAN handoff is already complete.", "cyan")
            continue

        current_ssid = current_ssids[entry.entry_id]
        if current_ssid == ssid:
            if not is_shelly_target_placement(item.device, current_ssid, ssid, opts.target_subnet):
                message = (
                    f"The Shelly reports '{ssid}' as primary but is reachable at {item.device.host}, "
                    f"outside {opts.target_subnet}; refusing automatic adoption."
                )
                set_migration_checkpoint(state, entry, item.device, "stage_failed", error=message)
                write_migration_state(state, opts.state_path)
                warn(f"'{title}': {message}")
                continue
            if not opts.confirm(title, f"Adopt existing target-WLAN address {item.device.host} and finalize Home Assistant credentials"):
                continue
            set_migration_checkpoint(state, entry, item.device, "discovered", item.device.host, item.device.port)
            write_migration_state(state, opts.state_path)
            staged.append(item)
            target_devices[item.device.mac] = item.device
            say(f"Adopting '{title}' at {item.device.host}; primary WLAN and target subnet are already correct.", "cyan")
            continue

        if not opts.confirm(title, f"Preserve the current WLAN as fallback, switch to '{ssid}', and verify VLAN placement"):
            continue
        try:
            if item.device.protected:
                get_shelly_settings(item.device, device_password)
            old_ssid = current_ssid
            if not old_ssid or not old_ssid.strip():
                raise MigrationError("The Shelly current primary WLAN could not be read.")
            set_shelly_coiot(item.device, f"{opts.home_assistant_ip}:5683", device_password)
            set_shelly_fallback_wifi(item.device, old_ssid, old_wifi_password, device_password)
            set_migration_checkpoint(state, entry, item.device, "staged", old_ssid=old_ssid)
            state["targetSsid"] = ssid
            write_migration_state(state, opts.state_path)
            try:
                set_shelly_primary_wifi(item.device, ssid, wifi_password, device_password)
            except MigrationError as exc:
                warn(f"'{title}' closed or failed the primary-WLAN request ({exc}); VLAN discovery will determine whether it was applied.")
            set_migration_checkpoint(state, entry, item.device, "transitioning", old_ssid=old_ssid)
            write_migration_state(state, opts.state_path)
            staged.append(item)
            fresh_staged.append(item)
            say(f"Switching '{title}' from '{old_ssid}' to '{ssid}'.", "green")
        except Exception as exc:  # noqa: BLE001
            set_migration_checkpoint(state, entry, item.device, "stage_failed", error=str(exc))
            write_migration_state(state, opts.state_path)
            report_error(f"{title}: {exc}")

    if not staged:
        raise MigrationError("No devices were staged successfully.")

    if fresh_staged:
        target_devices.update(
            wait_for_target_devices([r.device for r in fresh_staged], opts.target_subnet, opts.discovery_timeout)
        )

    for item in staged:
        entry, title = item.entry, item.entry.title
        if item.device.mac not in target_devices:
            message = (
                f"Device was not discovered on {opts.target_subnet}. It should remain on or fall back to its old WLAN; "
                "the fallback was left enabled."
            )
            set_migration_checkpoint(state, entry, item.device, "transition_failed", error=message)
            write_migration_state(state, opts.state_path)
            warn(f"'{title}': {message}")
            continue

        device = target_devices[item.device.mac]
        try:
            set_migration_checkpoint(state, entry, device, "discovered", device.host, device.port)
            write_migration_state(state, opts.state_path)

            device = wait_shelly_identity(device.host, device.port, device.mac)
            invoke_with_retry(lambda: disable_shelly_fallback_wifi(device, device_password), f"Disable fallback WLAN for '{title}'")
            invoke_with_retry(lambda: disable_shelly_cloud(device, device_password), f"Disable Shelly Cloud for '{title}'")

            if not set_shelly_ntp(device, opts.ntp_servers, device_password):
                warn(f"'{title}' did not synchronize with either configured PTB server.")

            set_ha_shelly_address(opts.home_assistant_url, token, entry.entry_id, device.host, device.port, False)
            if not wait_ha_entry_loaded(opts.home_assistant_url, token, entry.entry_id):
                raise MigrationError("Home Assistant did not load the Shelly after its address was updated.")

            device = protect_shelly_and_home_assistant(
                device, entry, opts.home_assistant_url, opts.home_assistant_websocket_url, token, device_password
            )
            set_migration_checkpoint(state, entry, device, "complete", device.host, device.port)
            write_migration_state(state, opts.state_path)
            say(f"Completed '{title}' at {device.host}.", "green")
        except Exception as exc:  # noqa: BLE001
            set_migration_checkpoint(state, entry, device, "finalize_failed", device.host, device.port, error=str(exc))
            write_migration_state(state, opts.state_path)
            report_error(f"{title}: {exc}")

    say()
    say("Batch processing finished. The old SSID remained enabled throughout.", "cyan")
    say(f"Non-secret migration state: {opts.state_path}")


def invoke_shelly_migration(opts: Options) -> None:
    if not opts.home_assistant_url.strip():
        raise MigrationError("Supply --home-assistant-url or set the HOME_ASSISTANT_URL environment variable.")
    if not re.match(r"^https?://", opts.home_assistant_url):
        raise MigrationError("--home-assistant-url must start with http:// or https://.")
    if not opts.home_assistant_websocket_url:
        opts.home_assistant_websocket_url = f"ws://{opts.home_assistant_ip}:8123/api/websocket"

    token = read_secret("Home Assistant administrator token")
    inventory = get_ha_shelly_inventory(opts.home_assistant_url, token)
    inventory = select_inventory_entries(inventory, opts.device_titles)
    if not inventory:
        raise MigrationError("No matching Home Assistant Shelly entries were found.")

    if opts.mode == "audit":
        show_audit(get_reachable_inventory(inventory))
        return

    device_password = read_confirmed_secret("Shared Shelly administration password", 16, 50, True)

    if opts.mode == "verify":
        run_verify(opts, token, inventory, device_password)
    elif opts.mode == "protect":
        run_protect(opts, token, inventory, device_password)
    else:
        state = read_migration_state(opts.state_path)
        inventory = resolve_inventory_from_state(inventory, state)
        if opts.mode == "rollback-staged":
            run_rollback(opts, inventory, state, device_password)
        else:
            run_migrate(opts, token, inventory, state, device_password)


def parse_args(argv: list[str] | None = None) -> Options:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", nargs="?", default="audit", choices=["audit", "migrate", "protect", "verify", "rollback-staged"])
    parser.add_argument("--home-assistant-url", default=os.environ.get("HOME_ASSISTANT_URL", ""))
    parser.add_argument("--home-assistant-ip", default="192.168.178.10")
    parser.add_argument("--home-assistant-websocket-url", default="")
    parser.add_argument("--target-subnet", default="192.168.20.0/24")
    parser.add_argument("--ntp-server", dest="ntp_servers", action="append", help="repeatable; defaults to the two PTB servers")
    parser.add_argument("--batch-size", type=int, default=5)
    parser.add_argument("--device-title", dest="device_titles", action="append", default=[], help="wildcards allowed; repeatable")
    parser.add_argument("--discovery-timeout", type=int, default=300)
    parser.add_argument("--state-path", type=Path, default=DEFAULT_STATE_PATH)
    parser.add_argument("--dry-run", action="store_true", help="show what would change without changing anything")
    parser.add_argument("--yes", dest="assume_yes", action="store_true", help="do not ask for confirmation per device")
    args = parser.parse_args(argv)

    if not 1 <= args.batch_size <= 100:
        parser.error("--batch-size must be between 1 and 100")
    if not 30 <= args.discovery_timeout <= 1800:
        parser.error("--discovery-timeout must be between 30 and 1800")
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", args.home_assistant_ip):
        parser.error("--home-assistant-ip must be an IPv4 address")
    if args.home_assistant_websocket_url and not re.match(r"^wss?://", args.home_assistant_websocket_url):
        parser.error("--home-assistant-websocket-url must start with ws:// or wss://")

    return Options(
        mode=args.mode,
        home_assistant_url=args.home_assistant_url,
        home_assistant_ip=args.home_assistant_ip,
        home_assistant_websocket_url=args.home_assistant_websocket_url,
        target_subnet=args.target_subnet,
        ntp_servers=args.ntp_servers or list(DEFAULT_NTP_SERVERS),
        batch_size=args.batch_size,
        device_titles=args.device_titles,
        discovery_timeout=args.discovery_timeout,
        state_path=args.state_path,
        dry_run=args.dry_run,
        assume_yes=args.assume_yes,
    )


def main(argv: list[str] | None = None) -> int:
    opts = parse_args(argv)
    try:
        invoke_shelly_migration(opts)
    except (MigrationError, KeyboardInterrupt, EOFError) as exc:
        report_error(str(exc) or type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
