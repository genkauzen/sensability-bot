from __future__ import annotations

import time
from typing import Any

from sensability.config import Config
from sensability.db import AccountRow, Database
from sensability.jwt_util import jwt_payload_unverified
from sensability.slctl_client import SelectelClient
from sensability.slctl_constants import SLCTL_TOKEN_REFRESH_MAX_AGE_SEC
from sensability.twc_constants import (
    TWC_FLOAT_IP_BALANCE_THRESHOLD_RUB,
    TWC_MONTH_LIMIT_COOLDOWN_SEC,
)
from sensability.twc_client import (
    TimewebClient,
    deep_find_email,
    deep_find_full_name,
    finances_balance_rubles,
)

def _expire_limits(row: AccountRow, now: float) -> dict[str, Any]:
    patch: dict[str, Any] = {}
    if row.limited_by_month:
        if not row.limited_by_month_ts or now >= row.limited_by_month_ts + TWC_MONTH_LIMIT_COOLDOWN_SEC:
            patch["limited_by_month"] = 0
            patch["limited_by_month_ts"] = None
    if row.limited_by_day:
        if not row.limited_by_day_ts or now >= row.limited_by_day_ts + 86400:
            patch["limited_by_day"] = 0
            patch["limited_by_day_ts"] = None
    if row.slctl_rate_until is not None and now >= row.slctl_rate_until:
        patch["slctl_rate_until"] = None
    return patch


async def _sync_timeweb(
    db: Database, twc: TimewebClient, cfg: Config, name: str, row: AccountRow
) -> AccountRow | None:
    now = time.time()
    patch = _expire_limits(row, now)

    payload = jwt_payload_unverified(row.api_key)
    acc_login = str(payload.get("user") or payload.get("sub") or "") or None

    bal: float | None = None
    cur: str | None = None
    acc_email: str | None = None
    acc_fn: str | None = None
    try:
        fin = await twc.get_finances(row.api_key)
        bal, cur = finances_balance_rubles(fin)
        acc_fn = deep_find_full_name(fin) or acc_fn
    except Exception:
        pass
    try:
        st = await twc.get_account_status(row.api_key)
        acc_email = deep_find_email(st) or acc_email
        acc_fn = deep_find_full_name(st) or acc_fn
    except Exception:
        pass
    if not acc_email:
        try:
            ns = await twc.get_notification_settings(row.api_key)
            acc_email = deep_find_email(ns) or acc_email
            acc_fn = deep_find_full_name(ns) or acc_fn
        except Exception:
            pass

    limited_by_balance = False
    if bal is not None and bal < cfg.twc_minimum_rubles:
        limited_by_balance = True

    patch["acc_login"] = acc_login
    patch["acc_email"] = acc_email
    patch["acc_full_name"] = acc_fn
    patch["balance_cached"] = bal
    patch["currency"] = cur
    patch["limited_by_balance"] = 1 if limited_by_balance else 0

    await db.patch_account(name, patch)
    return await db.get_account(name)


async def _ensure_selectel_iam_token(
    db: Database, slctl: SelectelClient, name: str, row: AccountRow
) -> AccountRow:
    use_pw = (
        row.slctl_keystone_user
        and row.slctl_keystone_domain
        and row.slctl_keystone_password
    )
    if not use_pw:
        return row
    now = time.time()
    stale = (
        row.slctl_token_issued_ts is None
        or (now - row.slctl_token_issued_ts) > SLCTL_TOKEN_REFRESH_MAX_AGE_SEC
    )
    if not stale:
        return row
    tok = await slctl.issue_iam_token_by_password(
        row.slctl_keystone_user,
        row.slctl_keystone_domain,
        row.slctl_keystone_password,
    )
    await db.patch_account(
        name,
        {"api_key": tok, "slctl_token_issued_ts": now, "acc_login": row.slctl_keystone_user},
    )
    out = await db.get_account(name)
    return out if out else row


async def _sync_selectel(
    db: Database, slctl: SelectelClient, cfg: Config, name: str, row: AccountRow
) -> AccountRow | None:
    now = time.time()
    patch = _expire_limits(row, now)
    row = await _ensure_selectel_iam_token(db, slctl, name, row)
    billing_xt = (row.slctl_billing_x_token or cfg.slctl_billing_x_token or "").strip() or None
    bal, cur = await slctl.get_balance_rub(row.api_key, billing_x_token=billing_xt)
    limited_by_balance = bool(bal is not None and bal < cfg.slctl_minimum_rubles)
    patch["balance_cached"] = bal
    patch["currency"] = cur or "RUB"
    patch["limited_by_balance"] = 1 if limited_by_balance else 0
    await db.patch_account(name, patch)
    return await db.get_account(name)


async def sync_account(
    db: Database,
    twc: TimewebClient,
    slctl: SelectelClient,
    cfg: Config,
    name: str,
) -> AccountRow | None:
    row = await db.get_account(name)
    if not row:
        return None
    if row.provider == "selectel":
        return await _sync_selectel(db, slctl, cfg, name, row)
    return await _sync_timeweb(db, twc, cfg, name, row)


def account_prefers_floating_ip_probe(row: AccountRow) -> bool:
    """Баланс выше порога в рублях — перебор через заказ плавающего IPv4 (без ВМ)."""
    if row.provider != "timeweb":
        return False
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
    if row.provider == "selectel":
        if row.slctl_rate_until is not None and now < row.slctl_rate_until:
            return False
        if row.balance_cached is not None and row.balance_cached < cfg.slctl_minimum_rubles:
            return False
        return True
    if row.provider != "timeweb":
        return False
    if row.limited_by_month and row.limited_by_month_ts:
        if now < row.limited_by_month_ts + TWC_MONTH_LIMIT_COOLDOWN_SEC:
            return False
    if row.limited_by_day and row.limited_by_day_ts:
        if now < row.limited_by_day_ts + 86400:
            return False
    if row.balance_cached is not None and row.balance_cached < cfg.twc_minimum_rubles:
        return False
    return True
