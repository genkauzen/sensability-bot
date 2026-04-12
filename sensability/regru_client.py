from __future__ import annotations

import json
from typing import Any

import httpx


REGRU_API_BASE = "https://api.cloudvps.reg.ru"


class RegruApiError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"Reg.ru CloudVPS HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body


def regru_is_spb_region(reglet: dict[str, Any]) -> bool:
    slug = str(reglet.get("region_slug") or "").lower()
    return "spb" in slug


class RegruClient:
    """Bearer-токен из панели Облачные VPS → Настройки (док.: developers.cloudvps.reg.ru)."""

    def __init__(self, proxy: str | None) -> None:
        self._client = httpx.AsyncClient(
            proxy=proxy,
            timeout=httpx.Timeout(60.0, connect=30.0),
            headers={"Accept": "application/json"},
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def list_reglets(self, token: str) -> list[dict[str, Any]]:
        url = f"{REGRU_API_BASE}/v1/reglets"
        r = await self._client.get(
            url,
            headers={
                "Authorization": f"Bearer {token.strip()}",
                "Content-Type": "application/json",
            },
        )
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

    async def delete_reglet(self, token: str, reglet_id: int) -> None:
        url = f"{REGRU_API_BASE}/v1/reglets/{int(reglet_id)}"
        r = await self._client.delete(
            url,
            headers={
                "Authorization": f"Bearer {token.strip()}",
                "Content-Type": "application/json",
            },
        )
        if r.status_code >= 400:
            raise RegruApiError(r.status_code, r.text)
