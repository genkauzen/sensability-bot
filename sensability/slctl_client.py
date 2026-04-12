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


def _looks_like_money_balance_type(balance_type: str) -> bool:
    x = str(balance_type or "").strip().lower()
    if not x:
        return True
    keys = (
        "rub",
        "руб",
        "rur",
        "primary",
        "main",
        "real",
        "money",
        "prepaid",
        "account",
        "bonus",
        "бонус",
        "основ",
        "generic",
        "total",
        "баланс",
    )
    return any(k in x for k in keys)


def parse_v3_balances_payload(payload: dict[str, Any]) -> tuple[float | None, str | None]:
    """Разбор ответа GET /v3/balances (структура в доке Selectel не всегда с rub в balance_type)."""
    settings = payload.get("settings") if isinstance(payload.get("settings"), dict) else {}
    currency = str(settings.get("currency") or "RUB").strip().upper()
    if currency in ("RUR", "₽", ""):
        currency = "RUB"

    billings = payload.get("billings")
    if not isinstance(billings, list) or not billings:
        return None, None

    final_chunks: list[float] = []
    typed_lines: list[float] = []
    fallback_lines: list[float] = []

    for b in billings:
        if not isinstance(b, dict):
            continue
        for key in ("final_sum", "balances_values_sum"):
            if b.get(key) is None:
                continue
            try:
                final_chunks.append(float(b[key]))
            except (TypeError, ValueError):
                pass
        bals = b.get("balances")
        if not isinstance(bals, list):
            continue
        for bal in bals:
            if not isinstance(bal, dict):
                continue
            raw = bal.get("value")
            if raw is None:
                continue
            try:
                v = float(raw)
            except (TypeError, ValueError):
                continue
            bt = str(bal.get("balance_type") or "")
            if _looks_like_money_balance_type(bt):
                typed_lines.append(v)
            else:
                fallback_lines.append(v)

    if final_chunks:
        s = sum(final_chunks)
        if s != 0:
            return s, currency
        if typed_lines and any(x != 0 for x in typed_lines):
            return sum(typed_lines), currency
        if fallback_lines and any(x != 0 for x in fallback_lines):
            return sum(fallback_lines), currency
        return s, currency

    if typed_lines:
        return sum(typed_lines), currency
    if fallback_lines:
        return sum(fallback_lines), currency
    return None, None


def format_keystone_error(exc: SlctlApiError) -> str:
    """Краткое сообщение из ответа Keystone / IAM."""
    p = exc.parsed
    if isinstance(p, dict):
        err = p.get("error")
        if isinstance(err, dict):
            msg = err.get("message") or err.get("title")
            if msg:
                return str(msg)
        if "message" in p:
            return str(p["message"])
    return parse_error_message(exc)[:800]


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

    async def issue_iam_token_by_password(
        self,
        username: str,
        account_domain: str,
        password: str,
    ) -> str:
        """Keystone password grant → заголовок X-Subject-Token (IAM для аккаунта).

        Сначала запрос с scope по домену аккаунта (как в доке Selectel), при 401 — без scope
        (unscoped), на случай если доменный scope отклоняется.
        """
        url = f"{IDENTITY_URL_DEFAULT}/auth/tokens"
        dom = str(account_domain).strip()
        uname = username.strip()
        identity_block: dict[str, Any] = {
            "methods": ["password"],
            "password": {
                "user": {
                    "name": uname,
                    "domain": {"name": dom},
                    "password": password,
                }
            },
        }
        variants: list[dict[str, Any]] = [
            {"auth": {**{"identity": identity_block}, "scope": {"domain": {"name": dom}}}},
            {"auth": {"identity": identity_block}},
        ]
        last_exc: SlctlApiError | None = None
        for body in variants:
            r = await self._client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            token = r.headers.get("X-Subject-Token") or r.headers.get("x-subject-token")
            parsed: dict | None = None
            if r.text.strip():
                try:
                    parsed = json.loads(r.text)
                except json.JSONDecodeError:
                    parsed = None
            if r.status_code in (200, 201) and token:
                self._endpoint_cache.clear()
                return str(token).strip()
            last_exc = SlctlApiError(r.status_code, r.text[:1500], parsed)
            if r.status_code != 401:
                break
        assert last_exc is not None
        raise last_exc

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

    async def _get_balances_json(
        self, headers: dict[str, str]
    ) -> dict[str, Any] | None:
        url = f"{BILLING_BASE_DEFAULT}/v3/balances"
        try:
            h = {"Accept": "application/json", **headers}
            r = await self._client.get(url, headers=h)
            body = r.text
            if r.status_code >= 400:
                return None
            if not body.strip():
                return None
            data = json.loads(body)
            return data if isinstance(data, dict) else None
        except (httpx.HTTPError, json.JSONDecodeError, TypeError):
            return None

    async def get_balance_rub(
        self,
        iam_token: str,
        *,
        billing_x_token: str | None = None,
    ) -> tuple[float | None, str | None]:
        """GET /v3/balances. Статический ключ панели (X-Token) — как в офиц. примерах биллинга;
        IAM — X-Auth-Token + X-Subject-Token."""
        attempts: list[dict[str, str]] = []
        if billing_x_token and billing_x_token.strip():
            attempts.append({"X-Token": billing_x_token.strip()})
        attempts.append(
            {
                "X-Auth-Token": iam_token,
                "X-Subject-Token": iam_token,
            }
        )
        last: tuple[float | None, str | None] = (None, None)
        for hdr in attempts:
            raw = await self._get_balances_json(hdr)
            if not raw:
                continue
            payload = raw.get("data")
            if not isinstance(payload, dict):
                payload = raw
            if not isinstance(payload, dict):
                continue
            last = parse_v3_balances_payload(payload)
            if last[0] is not None:
                return last
        return last

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
