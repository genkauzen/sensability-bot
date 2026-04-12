from __future__ import annotations

import logging
import re

from sensability.config import Config
from sensability.db import AccountRow, Database
from sensability.ip_pool import ipv4_in_pool, load_networks
from sensability.regru_client import RegruClient, regru_ip_record_is_spb_ipv4, regru_is_spb_region
from sensability.regru_constants import REGRU_REGION_SPB

log = logging.getLogger("sensability.regru")

_ubuntu_re = re.compile(r"ubuntu|debian", re.I)


async def regru_pick_spb_plan_and_image(
    regru: RegruClient, token: str
) -> tuple[str, str | int] | None:
    """Минимальный тариф + образ ОС в openstack-spb1 для POST /v1/reglets."""
    try:
        plans = await regru.v2_plans(token, region=REGRU_REGION_SPB, page=1, per_page=80)
    except Exception:
        log.exception("regru v2_plans")
        return None
    if not plans:
        return None

    def _mem(p: dict) -> int:
        for k in ("memory", "disk"):
            v = p.get(k)
            if v is None:
                continue
            try:
                return int(v)
            except (TypeError, ValueError):
                pass
        return 999999

    plans.sort(key=_mem)
    size_slug = str(plans[0].get("slug") or "").strip()
    if not size_slug:
        return None
    try:
        images = await regru.v2_images(token, region=REGRU_REGION_SPB, page=1, per_page=50)
    except Exception:
        log.exception("regru v2_images")
        return None
    if not images:
        return None
    scored = sorted(
        images,
        key=lambda i: (0 if _ubuntu_re.search(str(i.get("name") or "")) else 1, str(i.get("name"))),
    )
    for img in scored:
        slug = img.get("slug")
        if slug is not None and str(slug).strip():
            return size_slug, slug if isinstance(slug, int) else str(slug).strip()
    return None


async def regru_refresh_whitelist(
    db: Database,
    regru: RegruClient,
    cfg: Config,
    name: str,
    row: AccountRow,
    *,
    delete_bot_vms: bool,
) -> None:
    """ВМ в регионе Санкт-Петербург (region_slug содержит spb): IP из subnets.txt → белый список.
    При delete_bot_vms — удаляются только ВМ с именем {TWC_VM_NAME}-regru-*, не в ПНА и не в белом списке."""
    nets = load_networks(str(cfg.subnets_path))
    try:
        reglets = await regru.list_reglets(row.api_key)
    except Exception:
        log.exception("regru list_reglets %s", name)
        return

    wl = set(db.whitelist_regru_ids(row))
    wl_ip = set(db.whitelist_regru_ip_ids(row))
    prefix = f"{cfg.twc_vm_name}-regru-".lower()

    for raw in reglets:
        if not regru_is_spb_region(raw):
            continue
        rid = raw.get("id")
        try:
            rid_i = int(rid)
        except (TypeError, ValueError):
            continue
        ip = str(raw.get("ip") or "").strip()
        if ip and ipv4_in_pool(ip, nets):
            if rid_i not in wl:
                await db.append_whitelist_regru(name, rid_i)
                wl.add(rid_i)
            continue
        if not delete_bot_vms:
            continue
        if rid_i in wl:
            continue
        nm = str(raw.get("name") or "").strip().lower()
        if nm.startswith(prefix):
            try:
                await regru.delete_reglet(row.api_key, rid_i)
            except Exception:
                log.exception("regru delete_reglet %s id=%s", name, rid_i)

    try:
        ips = await regru.list_ips(row.api_key)
    except Exception:
        log.exception("regru list_ips whitelist %s", name)
        return
    for rec in ips:
        if not isinstance(rec, dict) or not regru_ip_record_is_spb_ipv4(rec):
            continue
        ip_s = str(rec.get("ip") or "").strip()
        if not ip_s or ip_s.count(".") != 3:
            continue
        try:
            ip_id = int(rec.get("id"))
        except (TypeError, ValueError):
            continue
        if ipv4_in_pool(ip_s, nets) and ip_id not in wl_ip:
            await db.append_whitelist_regru_ip(name, ip_id)
            wl_ip.add(ip_id)
