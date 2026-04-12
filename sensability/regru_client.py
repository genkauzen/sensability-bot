from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from sensability.regru_constants import REGRU_REGION_SPB
from sensability.twc_debug import (
    TwcApiDebugController,
    build_request_debug_html,
    build_response_debug_html,
)


REGRU_API_BASE = "https://api.cloudvps.reg.ru"


class RegruApiError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"Reg.ru CloudVPS HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body


def regru_is_spb_region(reglet: dict[str, Any]) -> bool:
    slug = str(reglet.get("region_slug") or "").lower()
    return "spb" in slug


def regru_ip_record_is_spb_ipv4(rec: dict[str, Any]) -> bool:
    t = str(rec.get("type") or "").lower()
    if t != "ipv4":
        return False
    slug = str(rec.get("region_slug") or "").lower()
    if not slug:
        return True
    return "spb" in slug


class RegruClient:
    """Bearer-токен из панели Облачные VPS → Настройки (док.: developers.cloudvps.reg.ru)."""

    def __init__(
        self,
        proxy: str | None,
        *,
        debug_ctrl: TwcApiDebugController | None = None,
        debug_emit: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._debug_ctrl = debug_ctrl
        self._debug_emit = debug_emit
        self._client = httpx.AsyncClient(
            proxy=proxy,
            timeout=httpx.Timeout(90.0, connect=30.0),
            headers={"Accept": "application/json"},
            follow_redirects=True,
        )

    def _h(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token.strip()}",
            "Content-Type": "application/json",
        }

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _emit_debug_parts(self, parts: list[str]) -> None:
        emit = self._debug_emit
        if not emit or not parts:
            return
        for chunk in parts:
            await emit(chunk)

    def _path_disp(self, url: str) -> str:
        if url.startswith(REGRU_API_BASE):
            rest = url[len(REGRU_API_BASE) :]
            return rest if rest else "/"
        return url

    async def _raw(
        self,
        method: str,
        url: str,
        token: str,
        *,
        json_body: Any | None = None,
    ) -> httpx.Response:
        path_disp = self._path_disp(url)
        dbg = self._debug_ctrl
        if dbg and dbg.mode in ("full", "mid"):
            await self._emit_debug_parts(
                build_request_debug_html(
                    dbg.mode, method, path_disp, json_body, service_label="Reg.ru"
                )
            )
        r = await self._client.request(method, url, headers=self._h(token), json=json_body)
        body = r.text
        parsed: Any = None
        if body.strip():
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = None
        if dbg and dbg.mode in ("full", "mid"):
            await self._emit_debug_parts(
                build_response_debug_html(
                    dbg.mode,
                    method,
                    path_disp,
                    r.status_code,
                    body,
                    parsed,
                    r.is_success,
                    service_label="Reg.ru",
                )
            )
        return r

    async def list_reglets(self, token: str) -> list[dict[str, Any]]:
        url = f"{REGRU_API_BASE}/v1/reglets"
        r = await self._raw("GET", url, token)
        body = r.text
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, body)
        try:
            data = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError as e:
            raise RegruApiError(r.status_code, body or str(e)) from e
        reglets = data.get("reglets") if isinstance(data, dict) else None
        if not isinstance(reglets, list):
            return []
        return [x for x in reglets if isinstance(x, dict)]

    async def get_reglet(self, token: str, reglet_id: int) -> dict[str, Any]:
        url = f"{REGRU_API_BASE}/v1/reglets/{int(reglet_id)}"
        r = await self._raw("GET", url, token)
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, r.text)
        try:
            data = json.loads(r.text) if r.text.strip() else {}
        except json.JSONDecodeError as e:
            raise RegruApiError(r.status_code, r.text) from e
        reglet = data.get("reglet") if isinstance(data, dict) else None
        return reglet if isinstance(reglet, dict) else {}

    async def delete_reglet(self, token: str, reglet_id: int) -> None:
        url = f"{REGRU_API_BASE}/v1/reglets/{int(reglet_id)}"
        r = await self._raw("DELETE", url, token)
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, r.text)

    async def get_balance_data(self, token: str) -> dict[str, Any] | None:
        url = f"{REGRU_API_BASE}/v1/balance_data"
        r = await self._raw("GET", url, token)
        if r.status_code >= 400:
            return None
        try:
            data = json.loads(r.text) if r.text.strip() else {}
        except json.JSONDecodeError:
            return None
        bd = data.get("balance_data") if isinstance(data, dict) else None
        return bd if isinstance(bd, dict) else None

    async def v2_plans(
        self, token: str, *, region: str = REGRU_REGION_SPB, page: int = 1, per_page: int = 50
    ) -> list[dict[str, Any]]:
        url = (
            f"{REGRU_API_BASE}/v2/plans"
            f"?region={region}&page={page}&items_per_page={per_page}"
        )
        r = await self._raw("GET", url, token)
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, r.text)
        data = json.loads(r.text) if r.text.strip() else {}
        plans = data.get("plans") if isinstance(data, dict) else None
        return [x for x in plans if isinstance(x, dict)] if isinstance(plans, list) else []

    async def v2_images(
        self,
        token: str,
        *,
        region: str = REGRU_REGION_SPB,
        page: int = 1,
        per_page: int = 50,
        image_type: str = "distribution",
    ) -> list[dict[str, Any]]:
        url = (
            f"{REGRU_API_BASE}/v2/images"
            f"?region={region}&page={page}&items_per_page={per_page}&type={image_type}"
        )
        r = await self._raw("GET", url, token)
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, r.text)
        data = json.loads(r.text) if r.text.strip() else {}
        imgs = data.get("images") if isinstance(data, dict) else None
        return [x for x in imgs if isinstance(x, dict)] if isinstance(imgs, list) else []

    async def create_reglet(
        self,
        token: str,
        *,
        name: str,
        size_slug: str,
        image_slug: str | int,
    ) -> dict[str, Any]:
        url = f"{REGRU_API_BASE}/v1/reglets"
        body: dict[str, Any] = {
            "name": name,
            "size": size_slug,
            "image": image_slug,
        }
        r = await self._raw("POST", url, token, json_body=body)
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, r.text)
        data = json.loads(r.text) if r.text.strip() else {}
        reglet = data.get("reglet") if isinstance(data, dict) else None
        return reglet if isinstance(reglet, dict) else {}

    async def list_ips(self, token: str, *, reglet_id: int | None = None) -> list[dict[str, Any]]:
        url = f"{REGRU_API_BASE}/v1/ips"
        if reglet_id is not None:
            url = f"{url}?reglet_id={int(reglet_id)}"
        r = await self._raw("GET", url, token)
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, r.text)
        data = json.loads(r.text) if r.text.strip() else {}
        ips = data.get("ips") if isinstance(data, dict) else None
        return [x for x in ips if isinstance(x, dict)] if isinstance(ips, list) else []

    async def order_extra_ips(
        self, token: str, reglet_id: int, *, ipv4_count: int = 1
    ) -> None:
        url = f"{REGRU_API_BASE}/v1/ips"
        body = {"reglet_id": int(reglet_id), "ipv4_count": int(ipv4_count)}
        r = await self._raw("POST", url, token, json_body=body)
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, r.text)

    async def delete_ip(self, token: str, ip_identifier: str) -> None:
        """DELETE /v1/ips/{ip} — в доке идентификатор IPv4 или id."""
        ident = str(ip_identifier).strip()
        url = f"{REGRU_API_BASE}/v1/ips/{ident}"
        r = await self._raw("DELETE", url, token)
        if r.status_code >= 400 and r.status_code != 404:
            raise RegruApiError(r.status_code, r.text)
