from __future__ import annotations

import json
import re
from typing import Any

import httpx

IDENTITY_URL_DEFAULT = "https://cloud.api.selcloud.ru/identity/v3"
BILLING_BASE_DEFAULT = "https://api.selectel.ru"


class SlctlApiError(Exception):
    def __init__(self, status: int, body: str, parsed: dict | None = None) -> None:
        super().__init__(f"Selectel HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body
        self.parsed = parsed


def parse_error_message(exc: SlctlApiError) -> str:
    if exc.parsed:
        try:
            return json.dumps(exc.parsed, ensure_ascii=False)[:2000]
        except Exception:
            pass
    return exc.body or str(exc)


def _pick_catalog_url(catalog: list[dict[str, Any]], service_type: str, region: str) -> str | None:
    for cat in catalog:
        if cat.get("type") != service_type:
            continue
        eps = [e for e in (cat.get("endpoints") or []) if isinstance(e, dict)]
        public = [e for e in eps if str(e.get("interface") or "") == "public"]
        pool = public if public else eps
        best: tuple[int, str] | None = None
        for ep in pool:
            reg = str(ep.get("region_id") or ep.get("region") or "")
            url = str(ep.get("url") or "").rstrip("/")
            if not url:
                continue
            score = 0
            if reg == region:
                score += 20
            if best is None or score > best[0]:
                best = (score, url)
        if best and best[0] > 0:
            return best[1]
        for ep in pool:
            url = str(ep.get("url") or "").rstrip("/")
            if url:
                return url
    return None


def extract_public_ipv4_from_nova_server(server: dict[str, Any]) -> str | None:
    """Публичный IPv4 из Nova server.addresses (предпочитаем floating / не RFC1918)."""
    addrs = server.get("addresses")
    if not isinstance(addrs, dict):
        return None
    candidates: list[tuple[int, str]] = []
    for _net, lst in addrs.items():
        if not isinstance(lst, list):
            continue
        for item in lst:
            if not isinstance(item, dict):
                continue
            ver = item.get("version")
            if ver != 4:
                continue
            ip = str(item.get("addr") or "").strip()
            if not ip or ip.count(".") != 3:
                continue
            typ = str(item.get("OS-EXT-IPS:type") or item.get("type") or "").lower()
            score = 0
            if "float" in typ:
                score += 20
            if not ip.startswith(("10.", "172.16.", "192.168.")):
                first = ip.split(".")[0]
                try:
                    o1 = int(first)
                    if o1 == 172 and 16 <= int(ip.split(".")[1]) <= 31:
                        pass
                    else:
                        score += 5
                except ValueError:
                    score += 5
            candidates.append((score, ip))
    if not candidates:
        return None
    candidates.sort(key=lambda x: -x[0])
    return candidates[0][1]


class SelectelClient:
    """IAM-токен (X-Auth-Token) + регион — Nova/Neutron по каталогу Keystone."""

    def __init__(self, proxy: str | None) -> None:
        self._proxy = proxy
        self._client = httpx.AsyncClient(
            proxy=proxy,
            timeout=httpx.Timeout(90.0, connect=30.0),
            headers={"Accept": "application/json"},
            follow_redirects=True,
        )
        self._endpoint_cache: dict[tuple[str, str], tuple[str, str]] = {}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        url: str,
        *,
        token: str | None = None,
        json_body: Any = None,
    ) -> Any:
        headers: dict[str, str] = {}
        if token:
            headers["X-Auth-Token"] = token
        r = await self._client.request(method, url, headers=headers, json=json_body)
        body = r.text
        parsed: dict | None = None
        ct = r.headers.get("content-type") or ""
        if "json" in ct.lower() and body.strip():
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = None
        if r.status_code >= 400:
            raise SlctlApiError(r.status_code, body, parsed)
        if parsed is not None:
            return parsed
        return body

    async def validate_token(self, token: str) -> dict[str, Any]:
        """Проверка IAM-токена и получение каталога."""
        url = f"{IDENTITY_URL_DEFAULT}/auth/tokens"
        headers = {"X-Auth-Token": token, "X-Subject-Token": token}
        r = await self._client.get(url, headers=headers)
        body = r.text
        parsed: dict[str, Any] | None = None
        if body.strip():
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = None
        if r.status_code >= 400:
            raise SlctlApiError(r.status_code, body, parsed)
        if not isinstance(parsed, dict):
            raise SlctlApiError(r.status_code, body or "empty", None)
        return parsed

    async def get_catalog_endpoints(self, token: str, region: str) -> tuple[str, str]:
        k = (token[:48], region)
        if k in self._endpoint_cache:
            return self._endpoint_cache[k]
        data = await self.validate_token(token)
        tok = data.get("token")
        catalog = tok.get("catalog") if isinstance(tok, dict) else None
        if not isinstance(catalog, list):
            catalog = []
        compute = _pick_catalog_url(catalog, "compute", region)
        network = _pick_catalog_url(catalog, "network", region)
        if not compute:
            compute = f"https://{region}.cloud.api.selcloud.ru/v2.1"
        if not network:
            network = f"https://{region}.cloud.api.selcloud.ru"
        self._endpoint_cache[k] = (compute, network)
        return compute, network

    async def get_balance_rub(self, token: str) -> tuple[float | None, str | None]:
        """GET /v3/balances — ищем рублёвый баланс."""
        url = f"{BILLING_BASE_DEFAULT}/v3/balances"
        try:
            data = await self._request("GET", url, token=token)
        except SlctlApiError:
            return None, None
        if not isinstance(data, dict):
            return None, None
        payload = data.get("data") or data
        if not isinstance(payload, dict):
            return None, None
        billings = payload.get("billings")
        if not isinstance(billings, list):
            return None, None
        best: float | None = None
        cur: str | None = None
        for b in billings:
            if not isinstance(b, dict):
                continue
            balances = b.get("balances")
            if not isinstance(balances, list):
                continue
            for bal in balances:
                if not isinstance(bal, dict):
                    continue
                bt = str(bal.get("balance_type") or "").lower()
                val = bal.get("value")
                if val is None:
                    continue
                try:
                    v = float(val)
                except (TypeError, ValueError):
                    continue
                if "rub" in bt or bt == "primary":
                    if best is None or v > best:
                        best = v
                        cur = "RUB"
        return best, cur

    async def list_flavors(self, token: str, compute_base: str) -> list[dict[str, Any]]:
        url = f"{compute_base.rstrip('/')}/flavors/detail"
        data = await self._request("GET", url, token=token)
        fl = data.get("flavors") if isinstance(data, dict) else None
        return [x for x in fl if isinstance(x, dict)] if isinstance(fl, list) else []

    async def list_images(self, token: str, compute_base: str) -> list[dict[str, Any]]:
        base = compute_base.rstrip("/")
        for path in ("/images/detail", "/images"):
            try:
                data = await self._request("GET", f"{base}{path}", token=token)
            except SlctlApiError:
                continue
            im = data.get("images") if isinstance(data, dict) else None
            if isinstance(im, list):
                return [x for x in im if isinstance(x, dict)]
        return []

    async def pick_flavor_id(self, token: str, compute_base: str) -> str | None:
        flavors = await self.list_flavors(token, compute_base)
        if not flavors:
            return None

        def sort_key(f: dict[str, Any]) -> tuple[int, int, str]:
            ram = f.get("ram") or 0
            vcpus = f.get("vcpus") or 0
            try:
                r = int(ram)
                v = int(vcpus)
            except (TypeError, ValueError):
                r, v = 999999, 999
            fid = str(f.get("id") or "")
            return (r, v, fid)

        flavors.sort(key=sort_key)
        for f in flavors:
            fid = str(f.get("id") or "")
            if fid:
                return fid
        return None

    _ubuntu_re = re.compile(r"ubuntu|debian", re.I)

    async def pick_image_id(self, token: str, compute_base: str) -> str | None:
        images = await self.list_images(token, compute_base)
        if not images:
            return None
        active = [i for i in images if str(i.get("status") or "").upper() == "ACTIVE"]
        pool = active if active else images

        def score(img: dict[str, Any]) -> tuple[int, str]:
            name = str(img.get("name") or "")
            s = 10 if self._ubuntu_re.search(name) else 0
            return (-s, name)

        pool.sort(key=score)
        for img in pool:
            iid = str(img.get("id") or "")
            if iid:
                return iid
        return None

    async def find_external_network_id(self, token: str, network_base: str) -> str | None:
        url = f"{network_base.rstrip('/')}/v2.0/networks"
        data = await self._request("GET", url, token=token)
        nets = data.get("networks") if isinstance(data, dict) else None
        if not isinstance(nets, list):
            return None
        for n in nets:
            if not isinstance(n, dict):
                continue
            if n.get("router:external") is True or str(n.get("router:external") or "").lower() == "true":
                nid = str(n.get("id") or "")
                if nid:
                    return nid
        for n in nets:
            if not isinstance(n, dict):
                continue
            name = str(n.get("name") or "").lower()
            if "external" in name or "ext" == name[:3]:
                nid = str(n.get("id") or "")
                if nid:
                    return nid
        return None

    async def create_server(
        self,
        token: str,
        region: str,
        name: str,
        *,
        flavor_ref: str | None,
        image_ref: str | None,
        network_uuid: str | None,
    ) -> dict[str, Any]:
        compute, network_base = await self.get_catalog_endpoints(token, region)
        assert compute
        if not flavor_ref:
            flavor_ref = await self.pick_flavor_id(token, compute)
        if not image_ref:
            image_ref = await self.pick_image_id(token, compute)
        if not flavor_ref or not image_ref:
            raise SlctlApiError(
                400,
                "Не удалось подобрать flavor/image в регионе — задайте SLCTL_FLAVOR_ID и SLCTL_IMAGE_ID в .env",
                None,
            )
        if not network_uuid:
            network_uuid = await self.find_external_network_id(token, network_base)
        body: dict[str, Any] = {
            "server": {
                "name": name,
                "imageRef": image_ref,
                "flavorRef": flavor_ref,
                "max_count": 1,
                "min_count": 1,
            }
        }
        if network_uuid:
            body["server"]["networks"] = [{"uuid": network_uuid}]
        url = f"{compute.rstrip('/')}/servers"
        return await self._request("POST", url, token=token, json_body=body)

    async def get_server(self, token: str, region: str, server_id: str) -> dict[str, Any]:
        compute, _ = await self.get_catalog_endpoints(token, region)
        url = f"{compute.rstrip('/')}/servers/{server_id}"
        data = await self._request("GET", url, token=token)
        srv = data.get("server") if isinstance(data, dict) else None
        return srv if isinstance(srv, dict) else {}

    async def delete_server(self, token: str, region: str, server_id: str) -> None:
        compute, _ = await self.get_catalog_endpoints(token, region)
        url = f"{compute.rstrip('/')}/servers/{server_id}"
        await self._request("DELETE", url, token=token)

    async def list_servers(self, token: str, region: str) -> list[dict[str, Any]]:
        compute, _ = await self.get_catalog_endpoints(token, region)
        url = f"{compute.rstrip('/')}/servers/detail"
        data = await self._request("GET", url, token=token)
        srvs = data.get("servers") if isinstance(data, dict) else None
        return [x for x in srvs if isinstance(x, dict)] if isinstance(srvs, list) else []


def is_slctl_rate_limit_error(status: int) -> bool:
    return status == 429 or status == 503
