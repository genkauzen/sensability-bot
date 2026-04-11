from __future__ import annotations

import csv
import io
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from sensability.account_sync import account_eligible_for_brute
from sensability.config import Config
from sensability.db import Database
from sensability.ip_pool import load_networks
from sensability.stats import StatsCollector
from sensability.tg_format import bold, code


def _local_midnight(ts: float, tz: ZoneInfo) -> float:
    dt = datetime.fromtimestamp(ts, tz=tz)
    start = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.timestamp()


async def build_daily_report(
    cfg: Config,
    db: Database,
    stats: StatsCollector,
    tz_name: str,
) -> tuple[str, bytes | None]:
    tz = ZoneInfo(tz_name)
    now = time.time()
    day_start = _local_midnight(now, tz)
    snap = stats.snapshot
    rows = await db.events_since(day_start)

    eligible = 0
    cooldown24 = 0
    month_lim = 0
    for acc in await db.list_accounts():
        if account_eligible_for_brute(acc, cfg):
            eligible += 1
        if acc.limited_by_day and acc.limited_by_day_ts and now < acc.limited_by_day_ts + 86400:
            cooldown24 += 1
        if acc.limited_by_month and acc.limited_by_month_ts and now < acc.limited_by_month_ts + 3600:
            month_lim += 1

    nets = load_networks(str(cfg.subnets_path))

    lines = [
        "📊 " + bold("Итоги дня"),
        "",
        f"• Попаданий в ПНА: {bold(str(snap.pool_hits))}",
        f"• ВМ создано (HTTP 201): {bold(str(snap.vm_created_ok))}",
        f"• Ошибок создания: {bold(str(snap.vm_created_fail))}",
        f"• ВМ удалено (IP вне ПНА): {bold(str(snap.vm_deleted_no_pool))}",
        f"• Проверок IPv4: {bold(str(snap.ipv4_checks))}",
        f"• Аккаунтов задействовано в переборе: {bold(str(len(snap.accounts_used)))}",
        f"• На «суточном» кулдауне сейчас: {bold(str(cooldown24))}",
        f"• Готовы к перебору (оценка): {bold(str(eligible))}",
        f"• Ошибка «пополните на месяц» (лимит час): {bold(str(month_lim))} акк. в ограничении",
        "",
        f"Пул ПНА: {code(str(len(nets)))} подсетей в {code(str(cfg.subnets_path))}",
    ]
    text = "\n".join(lines)

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts", "kind", "account", "detail"])
    for ts, kind, acc, detail in rows:
        w.writerow([datetime.fromtimestamp(ts, tz=tz).isoformat(), kind, acc or "", detail])
    csv_bytes = buf.getvalue().encode("utf-8")
    attachment = csv_bytes if rows else None
    return text, attachment
