from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, time as dtime
from collections.abc import Awaitable, Callable
from typing import Any

from telegram import Update
from telegram.ext import ContextTypes
from zoneinfo import ZoneInfo

from sensability.account_sync import account_prefers_floating_ip_probe, sync_account
from sensability.brute_worker import BruteOrchestrator
from sensability.config import Config
from sensability.db import AccountRow, Database
from sensability.ip_pool import load_networks
from sensability.notify import TelegramNotify
from sensability.report import build_daily_report
from sensability.slctl_client import SelectelClient, extract_public_ipv4_from_nova_server
from sensability.stats import StatsCollector
from sensability.tg_format import bold, code, esc
from sensability.twc_constants import (
    TWC_FLOAT_IP_ZONES,
    TWC_FLOAT_IP_ZONES_DB_KEY,
    TWC_MONTH_LIMIT_COOLDOWN_SEC,
)
from sensability.twc_client import (
    TimewebClient,
    extract_ipv4_from_server,
    finances_balance_rubles,
    floating_ip_record_from_response,
    timeweb_availability_zone_str,
    timeweb_server_zone_label,
)

log = logging.getLogger("sensability.handlers")

RE_TWC_FLOAT_ZONE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")

RE_ACCOUNT_ADD = re.compile(
    r"^/(?:account_add_twc|account_add)\s+(?:(timeweb|twc|selectel|slctl)\s+)?(.+)$",
    re.I,
)
RE_ACCOUNT_INFO = re.compile(r"^/account_info\s+(.+)$", re.I)
RE_ACCOUNT_DEL = re.compile(r"^/account_del\s+(\S+)\s*$", re.I)
RE_ACCOUNT_DISABLE = re.compile(r"^/(?:account_disable|accont_disable)\s+(\S+)\s*$", re.I)
RE_ACCOUNT_ENABLE = re.compile(r"^/account_enable\s+(\S+)\s*$", re.I)
RE_ACCOUNT_HEAL = re.compile(r"^/account_heal\s+(\S+)\s*$", re.I)
RE_ACCOUNT_MNG = re.compile(r"^/account_mng\s+(\S+)(?:\s+(.*))?$", re.I)
def _twc_account_resources_lines(
    db: Database,
    row: AccountRow,
    servers_payload: dict[str, Any],
    floats_payload: dict[str, Any],
) -> list[str]:
    w_srv = set(db.whitelist_server_ids(row))
    w_fl = set(db.whitelist_float_ids(row))
    lines: list[str] = []
    srvs = servers_payload.get("servers") if isinstance(servers_payload, dict) else None
    if not isinstance(srvs, list):
        srvs = []
    lines.append("┈ " + bold("ВМ в облаке") + f" ({code(str(len(srvs)))})")
    for s in srvs[:40]:
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        try:
            sid_i = int(sid) if sid is not None else 0
        except (TypeError, ValueError):
            sid_i = 0
        nm = str(s.get("name") or "—")
        st = str(s.get("status") or s.get("state") or "—")
        z = timeweb_server_zone_label(s)
        ips = extract_ipv4_from_server(s)
        ip_s = ", ".join(ips) if ips else "—"
        wl = " · 🔒 белый список" if sid_i and sid_i in w_srv else ""
        lines.append(
            f"   • id {code(str(sid))} {code(nm)} · {esc(st)} · {esc(z)} · IPv4 {code(ip_s)}{wl}"
        )
    if len(srvs) > 40:
        lines.append("   … " + bold("ещё") + f" {code(str(len(srvs) - 40))}")

    fl_raw = (
        floats_payload.get("floating_ips") or floats_payload.get("ips")
        if isinstance(floats_payload, dict)
        else None
    )
    if not isinstance(fl_raw, list):
        fl_raw = []
    lines.append("┈ " + bold("Плавающие IPv4") + f" ({code(str(len(fl_raw)))})")
    for f in fl_raw[:40]:
        if not isinstance(f, dict):
            continue
        inner = floating_ip_record_from_response(f) or f
        if not isinstance(inner, dict):
            continue
        fid = str(inner.get("id") or f.get("id") or "").strip() or "—"
        addr = inner.get("ip")
        if isinstance(addr, dict):
            addr = addr.get("ip")
        addr_s = str(addr).strip() if addr else "—"
        st = str(inner.get("status") or f.get("status") or "—")
        z = timeweb_availability_zone_str(inner.get("availability_zone")) or timeweb_availability_zone_str(
            f.get("availability_zone")
        )
        if not z:
            z = "—"
        wl = " · 🔒 белый список" if fid in w_fl else ""
        lines.append(f"   • {code(fid)} · {code(addr_s)} · {esc(st)} · {esc(z)}{wl}")
    if len(fl_raw) > 40:
        lines.append("   … " + bold("ещё") + f" {code(str(len(fl_raw) - 40))}")
    return lines


async def _twc_account_resources_block(db: Database, twc: TimewebClient, row: AccountRow) -> list[str]:
    srv_pl: dict[str, Any] = {}
    fl_pl: dict[str, Any] = {}
    errs: list[str] = []
    try:
        srv_pl = await twc.list_servers(row.api_key)
    except Exception as ex:
        errs.append("┈ " + bold("ВМ (API)") + f": ❌ {esc(str(ex)[:280])}")
    try:
        fl_pl = await twc.list_floating_ips(row.api_key)
    except Exception as ex:
        errs.append("┈ " + bold("Плавающие IP (API)") + f": ❌ {esc(str(ex)[:280])}")
    rest = _twc_account_resources_lines(db, row, srv_pl, fl_pl)
    return errs + rest


async def _slctl_account_resources_block(db: Database, slctl: SelectelClient, cfg: Config, row: AccountRow) -> list[str]:
    if row.provider != "selectel":
        return []
    reg = cfg.slctl_ip_location.strip() or "ru-2"
    w = set(db.whitelist_slctl_ids(row))
    try:
        srvs = await slctl.list_servers(row.api_key, reg)
    except Exception as ex:
        return ["┈ " + bold("ВМ Nova (Selectel)") + f": ❌ {esc(str(ex)[:280])}"]
    lines: list[str] = ["┈ " + bold("ВМ Nova (Selectel)") + f" ({code(str(len(srvs)))})"]
    for s in srvs[:30]:
        sid = str(s.get("id") or "").strip() or "—"
        ip = extract_public_ipv4_from_nova_server(s) or "—"
        wl = " · 🔒 белый список" if sid in w else ""
        lines.append(f"   • {code(sid)} · IPv4 {code(ip)}{wl}")
    return lines


def _uid(update: Update) -> str | None:
    u = update.effective_user
    return str(u.id) if u else None


def _terminal_ok(cfg: Config, update: Update) -> bool:
    if cfg.terminal_public_access:
        return True
    uid = _uid(update)
    return bool(uid and uid in cfg.terminal_user_ids)


def _verify_ok(cfg: Config, update: Update) -> bool:
    if cfg.accountverify_public_access:
        return True
    uid = _uid(update)
    return bool(uid and uid in cfg.accountverify_user_ids)


def _split_name_key(arg: str) -> tuple[str | None, str | None]:
    arg = arg.strip()
    i = arg.find("|")
    if i > 0:
        name, key = arg[:i].strip(), arg[i + 1 :].strip()
        if name and key:
            return name, key
    i = arg.find(":")
    if i <= 0:
        return None, None
    name, key = arg[:i].strip(), arg[i + 1 :].strip()
    if not name or not key:
        return None, None
    return name, key


async def handle_account_terminal_commands(
    cfg: Config,
    db: Database,
    twc: TimewebClient,
    slctl: SelectelClient,
    text: str,
    reply: Callable[[str], Awaitable[None]],
) -> bool:
    """Команды /account_list и /account_mng … — для терминала и топика verify. Возвращает True, если обработано."""
    raw = text.strip()
    low = raw.lower()
    if low == "/account_list":
        rows = await db.list_accounts()
        if not rows:
            await reply("📭 " + bold("Аккаунты") + " — пока пусто.")
            return True
        lines = [
            "📋 " + bold("Список аккаунтов") + f" · {code(str(len(rows)))} шт.",
            "",
        ]
        for r in rows[:60]:
            bal = "—" if r.balance_cached is None else f"{r.balance_cached:g}"
            cur = esc(r.currency or "")
            be = "🟢" if r.brute_enabled else "⚫"
            prov = "SL" if r.provider == "selectel" else "TW"
            lim = []
            if r.limited_by_balance:
                lim.append("баланс")
            if r.limited_by_month:
                lim.append("месяц")
            if r.limited_by_day:
                lim.append("сутки")
            lim_s = (" · ⚠️ " + ", ".join(lim)) if lim else ""
            lines.append(f"{be} [{prov}] {code(r.name)} · 💰 {code(bal)} {cur}{lim_s}")
        if len(rows) > 60:
            lines.append("")
            lines.append("… " + bold("ещё") + f" {code(str(len(rows) - 60))} — уточните по имени.")
        await reply("\n".join(lines))
        return True
    m = RE_ACCOUNT_MNG.match(raw)
    if not m:
        return False
    name = m.group(1).strip()
    rest = (m.group(2) or "").strip()
    flags = [x for x in rest.split() if x]
    row = await db.get_account(name)
    if not row:
        await reply("❌ " + bold("Аккаунт не найден") + f": {code(name)}")
        return True
    applied: list[str] = []
    unknown: list[str] = []
    for fl in flags:
        t = fl.lower()
        if t in ("-on", "-brute", "-brute_on"):
            await db.set_brute_enabled(name, True)
            applied.append("🟢 перебор " + bold("включён") + " (-on)")
        elif t in ("-off", "-brute_off"):
            await db.set_brute_enabled(name, False)
            applied.append("⚫ перебор " + bold("выключен") + " (-off)")
        elif t == "-heal":
            await db.heal_account(name)
            applied.append("🩹 " + bold("Все лимиты сброшены") + " (-heal)")
        elif t in ("-day", "-clearday"):
            await db.patch_account(
                name,
                {"limited_by_day": 0, "limited_by_day_ts": None},
            )
            applied.append("📅 " + bold("Суточный лимит снят") + " (-day)")
        elif t in ("-month", "-clearmonth"):
            await db.patch_account(
                name,
                {"limited_by_month": 0, "limited_by_month_ts": None},
            )
            applied.append("📆 " + bold("Месячный лимит снят") + " (-month)")
        elif t in ("-balance", "-balanceok", "-unlimit_balance"):
            await db.patch_account(name, {"limited_by_balance": 0})
            applied.append("💳 " + bold("Флаг «мало баланса» снят") + " (-balance)")
        else:
            unknown.append(fl)
    try:
        synced = await sync_account(db, twc, slctl, cfg, name)
        row = synced if synced else await db.get_account(name)
    except Exception:
        row = await db.get_account(name)
    assert row is not None
    now = time.time()
    left_day = "—"
    if row.limited_by_day and row.limited_by_day_ts:
        left = max(0, int(row.limited_by_day_ts + 86400 - now))
        left_day = f"{left // 3600}ч {(left % 3600) // 60}м"
    left_m = "—"
    if row.limited_by_month and row.limited_by_month_ts:
        lm = max(0, int(row.limited_by_month_ts + TWC_MONTH_LIMIT_COOLDOWN_SEC - now))
        left_m = f"{lm // 3600}ч {(lm % 3600) // 60}м"
    bal_s = "—" if row.balance_cached is None else f"{row.balance_cached:g}"
    if row.provider == "selectel":
        mode_ip = "📡 Selectel Neutron — плавающий IPv4"
        res_lines = await _slctl_account_resources_block(db, slctl, cfg, row)
    else:
        mode_ip = (
            "📡 плавающий IPv4 (без ВМ)"
            if account_prefers_floating_ip_probe(row)
            else "🖥 облачная ВМ Timeweb"
        )
        res_lines = await _twc_account_resources_block(db, twc, row)
    lim_lines: list[str] = [
        "┈ " + bold("Лимит месяца") + f": {'⚠️ да' if row.limited_by_month else '✅ нет'} (~{left_m})",
        "┈ " + bold("Лимит суток") + f": {'⚠️ да' if row.limited_by_day else '✅ нет'} (~{left_day})",
    ]
    prov_label = "Selectel" if row.provider == "selectel" else "Timeweb"
    panel = "\n".join(
        [
            "🪪 " + bold("Управление аккаунтом") + f" {code(name)}",
            "┈ " + bold("Провайдер") + f": {code(prov_label)}",
            "┈ " + bold("Email") + f": {code(row.acc_email or '—')}",
            "┈ " + bold("ФИО (личные данные)") + f": {code(row.acc_full_name or '—')}",
            "┈ " + bold("Login") + f": {code(row.acc_login or '—')}",
            "┈ " + bold("Баланс") + f": {code(bal_s)} {esc(row.currency or '')}",
            "┈ " + bold("Режим перебора") + f": {mode_ip}",
            "┈ " + bold("В подборе") + f": {'✅ да' if row.brute_enabled else '❌ нет'}",
            "┈ " + bold("Лимит баланса") + f": {'⚠️ да' if row.limited_by_balance else '✅ нет'}",
            *lim_lines,
            "",
            *res_lines,
            "",
            bold("Флаги") + ": "
            + code("-on")
            + " / "
            + code("-off")
            + " · "
            + code("-heal")
            + " · "
            + code("-day")
            + " · "
            + code("-month")
            + " · "
            + code("-balance"),
        ]
    )
    extra = ""
    if applied:
        extra = "\n\n" + bold("Выполнено") + "\n" + "\n".join(applied)
    if unknown:
        extra += "\n\n⚠️ " + bold("Не распознано") + ": " + ", ".join(code(u) for u in unknown)
    await reply(panel + extra)
    return True


def _ctx(
    application: Any,
) -> tuple[
    Config,
    Database,
    TimewebClient,
    SelectelClient,
    StatsCollector,
    TelegramNotify,
    BruteOrchestrator,
]:
    ctx = application.bot_data
    return (
        ctx["cfg"],
        ctx["db"],
        ctx["twc"],
        ctx["slctl"],
        ctx["stats"],
        ctx["notify"],
        ctx["orchestrator"],
    )


def _norm_debug_flag(tok: str) -> str | None:
    t = tok.lower().strip()
    if t in ("-full", "full"):
        return "full"
    if t in ("-mid", "mid"):
        return "mid"
    if t in ("-low", "low"):
        return "low"
    return None


def _parse_debug_command(parts: list[str]) -> tuple[str | None, str | None]:
    if not parts or parts[0].lower() != "/debug":
        return None, None
    if len(parts) == 1:
        return "timeweb", "full"
    p1 = parts[1].lower()
    aliases = {"timeweb": "timeweb", "twc": "timeweb", "selectel": "selectel", "slctl": "selectel"}
    if p1.startswith("-"):
        m = _norm_debug_flag(p1)
        return ("timeweb", m) if m else (None, None)
    if p1 not in aliases:
        return None, None
    svc = aliases[p1]
    if len(parts) == 2:
        return svc, "full"
    m = _norm_debug_flag(parts[2])
    return (svc, m) if m else (None, None)


async def on_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat:
        return
    app = context.application
    cfg, db, twc, slctl, stats, notify, _orch = _ctx(app)
    if update.effective_chat.id != cfg.group_id:
        return
    tid = update.message.message_thread_id
    text = (update.message.text or "").strip()
    if not text:
        return

    if tid == cfg.topic_terminal and _terminal_ok(cfg, update):
        await handle_terminal(update, context, text)
        return
    if tid == cfg.topic_accountverify and _verify_ok(cfg, update):
        await handle_accountverify(update, context, text)
        return


async def handle_terminal(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    cfg, db, twc, slctl, stats, notify, orch = _ctx(context.application)
    tid = update.message.message_thread_id if update.message else None
    low = text.lower().strip()

    if low in ("/help", "/commands", "commands", "help"):
        body = "\n".join(
            [
                bold("Sensability — терминал"),
                "/status — состояние бота",
                "/modules — активные компоненты",
                "/stop — приостановить перебор IP",
                "/continue — продолжить перебор",
                "/debug [timeweb|selectel] [-full|-mid|-low] — HTTP-лог в топик терминала",
                "/debug timeweb -mid — пример; без сервиса — как раньше (Timeweb)",
                "/timeweb mng — зоны плавающего IPv4; "
                + code("/timeweb mng -ip spb-3")
                + " или "
                + code("-ip default")
                + " (сброс)",
                "/account_list — список аккаунтов",
                "/account_mng имя — карточка и флаги: -on -off -heal -day -month -balance",
                "/account_add selectel name | IAM_token — подключить Selectel",
                "/help — этот список",
            ]
        )
        await notify.terminal_reply(tid, body)
        return

    parts = text.split()
    if parts and parts[0].lower() == "/timeweb":
        if len(parts) == 1:
            await notify.terminal_reply(
                tid,
                bold("Timeweb")
                + " — команды: "
                + code("/timeweb mng")
                + " (статус зон плавающего IPv4 и справка).",
            )
            return
        if parts[1].lower() != "mng":
            await notify.terminal_reply(
                tid,
                "Неизвестная подкоманда. Используйте " + code("/timeweb mng") + ".",
            )
            return
        rest = parts[2:]
        if not rest:
            z_eff = await db.get_twc_float_ip_zones_for_brute()
            custom_raw = await db.get_kv(TWC_FLOAT_IP_ZONES_DB_KEY)
            src = (
                bold("переопределение в БД")
                if custom_raw is not None
                else bold("по умолчанию") + f" ({code(', '.join(TWC_FLOAT_IP_ZONES))})"
            )
            await notify.terminal_reply(
                tid,
                "\n".join(
                    [
                        bold("Timeweb — зоны плавающего IPv4"),
                        "Источник: " + src,
                        "Перебор сейчас: " + code(", ".join(z_eff)),
                        "",
                        code("/timeweb mng -ip spb-3") + " — одна зона",
                        code("/timeweb mng -ip spb-3 msk-1") + " — несколько подряд",
                        code("/timeweb mng -ip spb-3,msk-1") + " — через запятую",
                        code("/timeweb mng -ip default") + " — сброс к умолчанию (СПб)",
                    ]
                ),
            )
            return
        if "-ip" not in rest:
            await notify.terminal_reply(
                tid,
                "Укажите " + code("-ip …") + " или вызовите " + code("/timeweb mng") + " без аргументов.",
            )
            return
        ip_i = rest.index("-ip")
        zone_tokens: list[str] = []
        for t in rest[ip_i + 1 :]:
            if t.startswith("-") and t.lower() != "-ip":
                break
            for piece in t.split(","):
                p = piece.strip()
                if p:
                    zone_tokens.append(p)
        if not zone_tokens:
            await notify.terminal_reply(tid, "После " + code("-ip") + " укажите хотя бы одну зону.")
            return
        if len(zone_tokens) == 1 and zone_tokens[0].lower() in ("default", "reset"):
            await db.delete_kv(TWC_FLOAT_IP_ZONES_DB_KEY)
            z_eff = await db.get_twc_float_ip_zones_for_brute()
            await notify.terminal_reply(
                tid,
                "✅ Сброс к умолчанию. Перебор: " + code(", ".join(z_eff)),
            )
            return
        bad = [z for z in zone_tokens if not RE_TWC_FLOAT_ZONE.match(z)]
        if bad:
            await notify.terminal_reply(
                tid,
                "Некорректные имена зон: " + ", ".join(code(x) for x in bad),
            )
            return
        await db.set_kv(TWC_FLOAT_IP_ZONES_DB_KEY, json.dumps(zone_tokens, ensure_ascii=False))
        await notify.terminal_reply(
            tid,
            "✅ Зоны плавающего IPv4: " + code(", ".join(zone_tokens)),
        )
        return

    if parts and parts[0].lower() == "/debug":
        svc_id, mode = _parse_debug_command(parts)
        if svc_id is None or mode is None:
            await notify.terminal_reply(
                tid,
                "\n".join(
                    [
                        bold("Формат /debug"),
                        code("/debug") + " или " + code("/debug timeweb") + " — полный лог Timeweb",
                        code("/debug -mid") + " — краткий Timeweb (как раньше)",
                        code("/debug timeweb -low") + " — выкл Timeweb",
                        code("/debug selectel -mid"),
                    ]
                ),
            )
            return
        ctrl_key = {"timeweb": "twc_debug", "selectel": "slctl_debug"}[svc_id]
        dbg = context.application.bot_data.get(ctrl_key)
        if dbg is None:
            await notify.terminal_reply(tid, "❌ " + bold("Отладка") + " для этого сервиса недоступна.")
            return
        dbg.mode = mode
        titles = {
            "timeweb": "Timeweb API",
            "selectel": "Selectel API",
        }
        if mode == "full":
            label = bold("полный") + " (запрос и ответ в цитате)"
        elif mode == "mid":
            label = bold("средний") + " (сжатый разбор без полного JSON)"
        else:
            label = bold("выкл")
        warn = ""
        if cfg.topic_terminal is None:
            warn = (
                "\n⚠️ "
                + bold("TOPIC_ID_TERMINAL")
                + " не задан — лог в Telegram не уйдёт."
            )
        await notify.terminal_reply(
            tid,
            "🔧 "
            + bold("Режим лога")
            + " "
            + bold(titles[svc_id])
            + ": "
            + label
            + "\nСообщения идут в топик терминала."
            + warn,
        )
        return

    async def _acc_reply(html: str) -> None:
        await notify.terminal_reply(tid, html)

    if await handle_account_terminal_commands(cfg, db, twc, slctl, text, _acc_reply):
        return

    if low == "/modules":
        await notify.terminal_reply(
            tid,
            "\n".join(
                [
                    bold("Модули"),
                    "• Перебор IPv4 / Timeweb API — " + code("brute_worker"),
                    "• Синхронизация аккаунтов — " + code("account_sync"),
                    "• SQLite — " + code("db"),
                    "• Telegram — " + code("python-telegram-bot"),
                ]
            ),
        )
        return

    if low == "/status":
        snap = stats.snapshot
        tw_nets = load_networks(str(cfg.timeweb_subnets_path))
        sl_nets = load_networks(str(cfg.selectel_subnets_path))
        started = float(context.application.bot_data.get("started_at", time.time()))
        up = int(time.time() - started)
        body = "\n".join(
            [
                "🤖 " + bold("Sensability"),
                f"Версия: {code('1.0.0')}",
                f"Аптайм: {code(str(up))} с",
                f"Whitelist Timeweb: {code(str(len(tw_nets)))}",
                f"Whitelist Selectel: {code(str(len(sl_nets)))}",
                f"Проверок IPv4 (сессия): {code(str(snap.ipv4_checks))}",
                f"Whitelist (сессия): {code(str(snap.pool_hits))}",
                f"Параллельных аккаунтов: {code(str(cfg.twc_atmoment_acc))}",
                f"Перебор: {code('на паузе' if orch.is_brute_paused() else 'активен')}",
            ]
        )
        await notify.terminal_reply(tid, body)
        return

    if low == "/stop":
        orch.set_brute_paused(True)
        await notify.terminal_reply(tid, "⏸ " + bold("Перебор приостановлен") + "\nПродолжить: " + code("/continue"))
        return

    if low == "/continue":
        orch.set_brute_paused(False)
        await notify.terminal_reply(tid, "▶️ " + bold("Перебор возобновлён"))
        return

    await notify.terminal_reply(tid, "Неизвестная команда. /help")


async def handle_accountverify(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    cfg, db, twc, slctl, stats, notify, _orch = _ctx(context.application)
    tid = update.message.message_thread_id if update.message else None

    async def _vreply(html: str) -> None:
        await notify.accountverify_reply(tid, html)

    if await handle_account_terminal_commands(cfg, db, twc, slctl, text, _vreply):
        return

    m = RE_ACCOUNT_ADD.match(text)
    if m:
        prov_raw = (m.group(1) or "").strip().lower()
        rest = (m.group(2) or "").strip()
        prov = "selectel" if prov_raw in ("selectel", "slctl") else "timeweb"
        bal: float | None = None
        cur: str | None = None
        name, key = _split_name_key(rest)
        if not name or not key:
            await notify.accountverify_reply(
                tid,
                "\n".join(
                    [
                        "Форматы:",
                        code("/account_add timeweb name | token"),
                        code("/account_add selectel name | IAM_token"),
                    ]
                ),
            )
            return
        if prov == "selectel":
            try:
                await slctl.validate_token(key)
                bal, cur = await slctl.get_balance_rub(key)
            except Exception as ex:
                await notify.accountverify_reply(tid, f"❌ Selectel IAM токен не подошёл: {esc(str(ex)[:500])}")
                return
        else:
            try:
                fin = await twc.get_finances(key)
                bal, cur = finances_balance_rubles(fin)
            except Exception as ex:
                await notify.accountverify_reply(tid, f"❌ API ключ не подошёл: {esc(str(ex)[:400])}")
                return
        await db.add_account(name, key, provider=prov)
        row = await sync_account(db, twc, slctl, cfg, name)
        em = row.acc_email if row else None
        lg = row.acc_login if row else None
        fn = row.acc_full_name if row else None
        bal_s = None if not row or row.balance_cached is None else row.balance_cached
        cur_s = (row.currency or "") if row else ""
        prov_label = "Selectel" if prov == "selectel" else "Timeweb"
        await notify.accountverify_reply(
            tid,
            "\n".join(
                [
                    "✅ " + bold("Аккаунт подключён") + f" ({prov_label})",
                    "┈ " + bold("Имя в боте") + f" {code(name)}",
                    "┈ " + bold("Email") + f" {code(em or '—')}",
                    "┈ " + bold("ФИО") + f" {code(fn or '—')}",
                    "┈ " + bold("Login") + f" {code(lg or '—')}",
                    "┈ "
                    + bold("Баланс")
                    + f" {code('—' if bal_s is None else str(bal_s))} {esc(cur_s)}",
                ]
            ),
        )
        return

    m = RE_ACCOUNT_INFO.match(text)
    if m:
        name = m.group(1).strip()
        row = await db.get_account(name)
        if not row:
            await notify.accountverify_reply(tid, "Не найден: " + code(name))
            return
        try:
            synced = await sync_account(db, twc, slctl, cfg, name)
            if synced:
                row = synced
        except Exception:
            pass
        now = time.time()
        left_day = "—"
        if row.limited_by_day and row.limited_by_day_ts:
            left = max(0, int(row.limited_by_day_ts + 86400 - now))
            left_day = f"{left // 3600}ч {(left % 3600) // 60}м"
        left_m = "—"
        if row.limited_by_month and row.limited_by_month_ts:
            lm = max(0, int(row.limited_by_month_ts + TWC_MONTH_LIMIT_COOLDOWN_SEC - now))
            left_m = f"{lm // 3600}ч {(lm % 3600) // 60}м"
        bal_s = "—" if row.balance_cached is None else f"{row.balance_cached:g}"
        if row.provider == "selectel":
            mode_ip = "📡 Selectel Neutron — плавающий IPv4"
            res_lines = await _slctl_account_resources_block(db, slctl, cfg, row)
        else:
            mode_ip = (
                "📡 плавающий IPv4 (без ВМ)"
                if account_prefers_floating_ip_probe(row)
                else "🖥 облачная ВМ Timeweb"
            )
            res_lines = await _twc_account_resources_block(db, twc, row)
        lim_lines: list[str] = [
            "┈ " + bold("Лимит месяца") + f": {'⚠️ да' if row.limited_by_month else '✅ нет'} (~{left_m})",
            "┈ " + bold("Лимит суток") + f": {'⚠️ да' if row.limited_by_day else '✅ нет'} (~{left_day})",
        ]
        prov_card = "Selectel" if row.provider == "selectel" else "Timeweb"
        body = "\n".join(
            [
                "🪪 " + bold("Карточка аккаунта") + f" {code(name)}",
                "┈ " + bold("Провайдер") + f": {code(prov_card)}",
                "┈ " + bold("Email") + f": {code(row.acc_email or '—')}",
                "┈ " + bold("ФИО (личные данные)") + f": {code(row.acc_full_name or '—')}",
                "┈ " + bold("Login") + f": {code(row.acc_login or '—')}",
                "┈ " + bold("Баланс") + f": {code(bal_s)} {esc(row.currency or '')}",
                "┈ " + bold("Режим перебора") + f": {mode_ip}",
                "┈ " + bold("В подборе") + f": {'✅ да' if row.brute_enabled else '❌ нет'}",
                "┈ " + bold("Лимит баланса") + f": {'⚠️ да' if row.limited_by_balance else '✅ нет'}",
                *lim_lines,
                "",
                *res_lines,
            ]
        )
        await notify.accountverify_reply(tid, body)
        return

    m = RE_ACCOUNT_DEL.match(text)
    if m:
        ok = await db.delete_account(m.group(1))
        await notify.accountverify_reply(tid, "Удалён." if ok else "Не найден.")
        return

    m = RE_ACCOUNT_DISABLE.match(text)
    if m:
        ok = await db.set_brute_enabled(m.group(1), False)
        await notify.accountverify_reply(tid, "Отключён от перебора." if ok else "Не найден.")
        return

    m = RE_ACCOUNT_ENABLE.match(text)
    if m:
        ok = await db.set_brute_enabled(m.group(1), True)
        await notify.accountverify_reply(tid, "Включён в перебор." if ok else "Не найден.")
        return

    m = RE_ACCOUNT_HEAL.match(text)
    if m:
        ok = await db.heal_account(m.group(1))
        await notify.accountverify_reply(tid, "Лимиты сброшены." if ok else "Не найден.")
        return

    await notify.accountverify_reply(
        tid,
        "\n".join(
            [
                bold("Команды аккаунтов"),
                code("/account_add timeweb name | token"),
                code("/account_add selectel name | IAM_token"),
                code("/account_info имя"),
                code("/account_list"),
                code("/account_mng имя") + " и флаги " + code("-on -off -heal -day -month -balance"),
                code("/account_del имя") + " · " + code("/account_enable") + " / " + code("/account_disable"),
            ]
        ),
    )


async def daily_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    app = context.application
    cfg: Config = app.bot_data["cfg"]
    db: Database = app.bot_data["db"]
    stats: StatsCollector = app.bot_data["stats"]
    notify: TelegramNotify = app.bot_data["notify"]
    tz = app.bot_data.get("tz", "Europe/Moscow")
    text, csv_bytes = await build_daily_report(cfg, db, stats, str(tz))
    await notify.updaywork(text)
    if csv_bytes:
        from telegram import InputFile

        await app.bot.send_document(
            chat_id=cfg.group_id,
            message_thread_id=cfg.topic_updaywork,
            document=InputFile(csv_bytes, filename=f"sensability-events-{datetime.now().date()}.csv"),
            caption="События за сутки (CSV)",
        )
    await stats.reset_day()


def schedule_daily(app: Any, cfg: Config) -> None:
    if not cfg.topic_updaywork:
        return
    parts = cfg.updaywork_upload_time.replace(" ", "").split(":")
    h = int(parts[0]) if parts else 0
    m = int(parts[1]) if len(parts) > 1 else 0
    tz_name = app.bot_data.get("tz", "Europe/Moscow")
    tz = ZoneInfo(str(tz_name))
    t = dtime(hour=h, minute=m, tzinfo=tz)
    jq = app.job_queue
    if jq is None:
        log.warning("JobQueue отключён — ежедневный отчёт недоступен")
        return
    jq.run_daily(daily_job, time=t, days=tuple(range(7)), name="daily_report")
