from __future__ import annotations

import logging

from sensability.config import Config
from sensability.db import AccountRow, Database
from sensability.ip_pool import ipv4_in_pool, load_networks
from sensability.regru_client import RegruClient, regru_is_spb_region

log = logging.getLogger("sensability.regru")


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
