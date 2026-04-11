from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from sensability.config import Config
from sensability.db import AccountRow, Database
from sensability.jwt_util import jwt_payload_unverified
from sensability.twc_constants import TWC_FLOAT_IP_BALANCE_THRESHOLD_RUB
from sensability.twc_client import TimewebClient, deep_find_email, finances_balance_rubles

if TYPE_CHECKING:
    pass


def _expire_limits(row: AccountRow, now: float) -> dict[str, Any]:
    patch: dict[str, Any] = {}
    if row.limited_by_month:
        if not row.limited_by_month_ts or now >= row.limited_by_month_ts + 3600:
            patch["limited_by_month"] = 0
            patch["limited_by_month_ts"] = None
    if row.limited_by_day:
        if not row.limited_by_day_ts or now >= row.limited_by_day_ts + 86400:
            patch["limited_by_day"] = 0
            patch["limited_by_day_ts"] = None
    return patch


async def sync_account(db: Database, twc: TimewebClient, cfg: Config, name: str) -> AccountRow | None:
    row = await db.get_account(name)
    if not row:
        return None
    now = time.time()
    patch = _expire_limits(row, now)

    payload = jwt_payload_unverified(row.api_key)
    acc_login = str(payload.get("user") or payload.get("sub") or "") or None

    bal: float | None = None
    cur: str | None = None
    acc_email: str | None = None
    try:
        fin = await twc.get_finances(row.api_key)
        bal, cur = finances_balance_rubles(fin)
    except Exception:
        pass
    try:
        st = await twc.get_account_status(row.api_key)
        acc_email = deep_find_email(st) or acc_email
    except Exception:
        pass
    if not acc_email:
        try:
            ns = await twc.get_notification_settings(row.api_key)
            acc_email = deep_find_email(ns) or acc_email
        except Exception:
            pass

    limited_by_balance = False
    if bal is not None and bal < cfg.twc_minimum_rubles:
        limited_by_balance = True

    patch["acc_login"] = acc_login
    patch["acc_email"] = acc_email
    patch["balance_cached"] = bal
    patch["currency"] = cur
    patch["limited_by_balance"] = 1 if limited_by_balance else 0

    await db.patch_account(name, patch)
    out = await db.get_account(name)
    return out


def account_prefers_floating_ip_probe(row: AccountRow) -> bool:
    """Баланс выше порога в рублях — перебор через заказ плавающего IPv4 (без ВМ)."""
    if row.balance_cached is None:
        return False
    cur = (row.currency or "").strip().upper()
    if cur and cur not in ("RUB", "RUR", "₽"):
        return False
    return row.balance_cached > TWC_FLOAT_IP_BALANCE_THRESHOLD_RUB


def account_eligible_for_brute(row: AccountRow, cfg: Config) -> bool:
    if not row.brute_enabled:
        return False
    if row.limited_by_balance:
        return False
    now = time.time()
    if row.limited_by_month and row.limited_by_month_ts:
        if now < row.limited_by_month_ts + 3600:
            return False
    if row.limited_by_day and row.limited_by_day_ts:
        if now < row.limited_by_day_ts + 86400:
            return False
    if row.balance_cached is not None and row.balance_cached < cfg.twc_minimum_rubles:
        return False
    return True
