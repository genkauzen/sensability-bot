from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from sensability.twc_debug import (
    TwcApiDebugController,
    build_request_debug_html,
    build_response_debug_html,
)

BASE = "https://api.timeweb.cloud"

MONTH_BALANCE_ERR_RE = re.compile(
    r"(месяц|месячн|monthly|\bmonth\b|на\s+месяц|оплатить\s+месяц)",
    re.IGNORECASE | re.UNICODE,
)


class TimewebApiError(Exception):
    def __init__(self, status: int, body: str, parsed: dict | None = None) -> None:
        super().__init__(f"TWC HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body
        self.parsed = parsed


def looks_like_month_balance_error(message: str) -> bool:
    if not message:
        return False
    if MONTH_BALANCE_ERR_RE.search(message):
        return True
    low = message.lower()
    return "пополн" in low and ("месяц" in low or "month" in low)


class TimewebClient:
    def __init__(
        self,
        proxy: str | None,
        *,
        debug_ctrl: TwcApiDebugController | None = None,
        debug_emit: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._proxy = proxy
        self._debug_ctrl = debug_ctrl
        self._debug_emit = debug_emit
        self._client = httpx.AsyncClient(
            base_url=BASE,
            proxy=proxy,
            timeout=httpx.Timeout(60.0, connect=30.0),
            headers={"Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _auth(self, api_key: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {api_key}"}

    async def _emit_debug_parts(self, parts: list[str]) -> None:
        emit = self._debug_emit
        if not emit or not parts:
            return
        for chunk in parts:
            await emit(chunk)

    async def _request(
        self,
        method: str,
        path: str,
        api_key: str,
        *,
        json_body: Any | None = None,
    ) -> Any:
        dbg = self._debug_ctrl
        if dbg and dbg.mode in ("full", "mid"):
            await self._emit_debug_parts(
                build_request_debug_html(dbg.mode, method, path, json_body)
            )

        r = await self._client.request(
            method,
            path,
            headers={**self._auth(api_key), "Content-Type": "application/json"},
            json=json_body,
        )
        text = r.text
        try:
            data = r.json()
        except Exception:
            data = None

        if dbg and dbg.mode in ("full", "mid"):
            await self._emit_debug_parts(
                build_response_debug_html(
                    dbg.mode, method, path, r.status_code, text, data, r.is_success
                )
            )

        if r.is_success:
            return data
        raise TimewebApiError(r.status_code, text, data if isinstance(data, dict) else None)

    async def get_finances(self, api_key: str) -> dict[str, Any]:
        data = await self._request("GET", "/api/v1/account/finances", api_key)
        assert isinstance(data, dict)
        return data

    async def get_account_status(self, api_key: str) -> dict[str, Any]:
        data = await self._request("GET", "/api/v1/account/status", api_key)
        assert isinstance(data, dict)
        return data

    async def get_notification_settings(self, api_key: str) -> dict[str, Any]:
        data = await self._request("GET", "/api/v1/account/notification-settings", api_key)
        assert isinstance(data, dict)
        return data

    async def create_server(self, api_key: str, body: dict[str, Any]) -> dict[str, Any]:
        data = await self._request("POST", "/api/v1/servers", api_key, json_body=body)
        assert isinstance(data, dict)
        return data

    async def get_server(self, api_key: str, server_id: int) -> dict[str, Any]:
        data = await self._request("GET", f"/api/v1/servers/{server_id}", api_key)
        assert isinstance(data, dict)
        return data

    async def get_server_ips(self, api_key: str, server_id: int) -> dict[str, Any]:
        data = await self._request("GET", f"/api/v1/servers/{server_id}/ips", api_key)
        assert isinstance(data, dict)
        return data

    async def shutdown_server(self, api_key: str, server_id: int) -> None:
        await self._request("POST", f"/api/v1/servers/{server_id}/shutdown", api_key, json_body={})

    async def delete_server(self, api_key: str, server_id: int) -> None:
        await self._request("DELETE", f"/api/v1/servers/{server_id}", api_key)


def extract_public_ipv4s(ips_payload: dict[str, Any]) -> list[str]:
    out: list[str] = []
    raw = ips_payload.get("server_ips") or ips_payload.get("ips") or []
    if isinstance(raw, dict):
        raw = raw.get("ips") or raw.get("items") or []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip") or item.get("address")
        if not ip:
            continue
        s = str(ip).strip()
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            continue
        if isinstance(a, ipaddress.IPv4Address):
            typ = (item.get("type") or item.get("family") or "").lower()
            if "v6" in typ or typ == "ipv6":
                continue
            out.append(s)
    return list(dict.fromkeys(out))


def extract_ipv4_from_server(server: dict[str, Any]) -> list[str]:
    found: list[str] = []
    nets = server.get("networks")
    if isinstance(nets, list):
        for n in nets:
            if not isinstance(n, dict):
                continue
            for key in ("ip", "floating_ip", "public_ip"):
                v = n.get(key)
                if not isinstance(v, str):
                    continue
                try:
                    a = ipaddress.ip_address(v.strip())
                except ValueError:
                    continue
                if isinstance(a, ipaddress.IPv4Address):
                    found.append(str(a))
    return list(dict.fromkeys(found))


def parse_error_message(exc: TimewebApiError) -> str:
    if not exc.parsed:
        return exc.body
    msg = exc.parsed.get("message")
    if isinstance(msg, list):
        return " ".join(str(x) for x in msg)
    if isinstance(msg, str):
        return msg
    return exc.body


def is_server_not_found(exc: Exception) -> bool:
    if isinstance(exc, TimewebApiError):
        if exc.status == 404:
            return True
        ec = (exc.parsed or {}).get("error_code")
        if ec == "server_not_found":
            return True
        msg = parse_error_message(exc).lower()
        if "server_not_found" in msg or "server with id" in msg:
            return True
    return False


def deep_find_email(obj: Any) -> str | None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in ("email", "e_mail", "mail") and isinstance(v, str) and "@" in v:
                return v
            sub = deep_find_email(v)
            if sub:
                return sub
    elif isinstance(obj, list):
        for it in obj:
            sub = deep_find_email(it)
            if sub:
                return sub
    return None


def finances_balance_rubles(finances: dict[str, Any]) -> tuple[float | None, str | None]:
    fin = finances.get("finances")
    if not isinstance(fin, dict):
        return None, None
    bal = fin.get("balance")
    cur = fin.get("currency")
    try:
        b = float(bal) if bal is not None else None
    except (TypeError, ValueError):
        b = None
    c = str(cur) if cur else None
    return b, c
