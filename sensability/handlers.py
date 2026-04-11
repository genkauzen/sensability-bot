from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, time as dtime
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from telegram import Update
from telegram.ext import ContextTypes
from zoneinfo import ZoneInfo

from sensability.account_sync import account_prefers_floating_ip_probe, sync_account
from sensability.brute_worker import BruteOrchestrator
from sensability.config import Config
from sensability.db import Database
from sensability.docker_ops import compose_command, compose_dir_ok
from sensability.ip_pool import load_networks
from sensability.notify import TelegramNotify
from sensability.report import build_daily_report
from sensability.stats import StatsCollector
from sensability.tg_format import bold, code, esc
from sensability.twc_client import TimewebClient, finances_balance_rubles

if TYPE_CHECKING:
    pass

log = logging.getLogger("sensability.handlers")

RE_ACCOUNT_ADD = re.compile(r"^/(?:account_add_twc|account_add)\s+(.+)$", re.I)
RE_ACCOUNT_INFO = re.compile(r"^/account_info\s+(.+)$", re.I)
RE_ACCOUNT_DEL = re.compile(r"^/account_del\s+(\S+)\s*$", re.I)
RE_ACCOUNT_DISABLE = re.compile(r"^/(?:account_disable|accont_disable)\s+(\S+)\s*$", re.I)
RE_ACCOUNT_ENABLE = re.compile(r"^/account_enable\s+(\S+)\s*$", re.I)
RE_ACCOUNT_HEAL = re.compile(r"^/account_heal\s+(\S+)\s*$", re.I)
RE_ACCOUNT_MNG = re.compile(r"^/account_mng\s+(\S+)(?:\s+(.*))?$", re.I)


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
            "📋 " + bold("Список аккаунтов Timeweb") + f" · {code(str(len(rows)))} шт.",
            "",
        ]
        for r in rows[:60]:
            bal = "—" if r.balance_cached is None else f"{r.balance_cached:g}"
            cur = esc(r.currency or "")
            be = "🟢" if r.brute_enabled else "⚫"
            lim = []
            if r.limited_by_balance:
                lim.append("баланс")
            if r.limited_by_month:
                lim.append("месяц")
            if r.limited_by_day:
                lim.append("сутки")
            lim_s = (" · ⚠️ " + ", ".join(lim)) if lim else ""
            lines.append(f"{be} {code(r.name)} · 💰 {code(bal)} {cur}{lim_s}")
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
    row = await db.get_account(name)
    assert row is not None
    now = time.time()
    left_day = "—"
    if row.limited_by_day and row.limited_by_day_ts:
        left = max(0, int(row.limited_by_day_ts + 86400 - now))
        left_day = f"{left // 3600}ч {(left % 3600) // 60}м"
    left_m = "—"
    if row.limited_by_month and row.limited_by_month_ts:
        lm = max(0, int(row.limited_by_month_ts + 3600 - now))
        left_m = f"{lm // 60}м {lm % 60}с"
    bal_s = "—" if row.balance_cached is None else f"{row.balance_cached:g}"
    mode_ip = (
        "📡 плавающий IPv4 (без ВМ)"
        if account_prefers_floating_ip_probe(row)
        else "🖥 облачная ВМ"
    )
    panel = "\n".join(
        [
            "🪪 " + bold("Управление аккаунтом") + f" {code(name)}",
            "┈ " + bold("Email") + f": {code(row.acc_email or '—')}",
            "┈ " + bold("Login") + f": {code(row.acc_login or '—')}",
            "┈ " + bold("Баланс") + f": {code(bal_s)} {esc(row.currency or '')}",
            "┈ " + bold("Режим перебора") + f": {mode_ip}",
            "┈ " + bold("В подборе") + f": {'✅ да' if row.brute_enabled else '❌ нет'}",
            "┈ " + bold("Лимит баланса") + f": {'⚠️ да' if row.limited_by_balance else '✅ нет'}",
            "┈ " + bold("Лимит месяца") + f": {'⚠️ да' if row.limited_by_month else '✅ нет'} (~{left_m})",
            "┈ " + bold("Лимит суток") + f": {'⚠️ да' if row.limited_by_day else '✅ нет'} (~{left_day})",
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


def _ctx(application: Any) -> tuple[Config, Database, TimewebClient, StatsCollector, TelegramNotify, BruteOrchestrator]:
    ctx = application.bot_data
    return (
        ctx["cfg"],
        ctx["db"],
        ctx["twc"],
        ctx["stats"],
        ctx["notify"],
        ctx["orchestrator"],
    )


async def on_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat:
        return
    app = context.application
    cfg, db, twc, stats, notify, _orch = _ctx(app)
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
    cfg, db, twc, stats, notify, orch = _ctx(context.application)
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
                "/debug — лог TWC API: полные запрос и ответ (в blockquote)",
                "/debug -mid — краткий лог (зона, параметры ВМ, суть ответа)",
                "/debug -low — отключить лог TWC",
                "/account_list — список аккаунтов Timeweb",
                "/account_mng имя — карточка и флаги: -on -off -heal -day -month -balance",
                "/drop — docker compose down",
                "/restart — пересоздать контейнеры (force-recreate)",
                "/rebuild — build --no-cache + up force-recreate",
                "/help — этот список",
            ]
        )
        await notify.terminal_reply(tid, body)
        return

    parts = text.split()
    if parts and parts[0].lower() == "/debug":
        dbg = context.application.bot_data.get("twc_debug")
        if dbg is None:
            await notify.terminal_reply(tid, "❌ " + bold("Отладка TWC") + " недоступна.")
            return
        if len(parts) == 1:
            dbg.mode = "full"
            label = bold("полный") + " (каждый запрос и ответ — в цитате Telegram)"
        elif len(parts) == 2:
            flag = parts[1].lower()
            if flag in ("-mid", "mid"):
                dbg.mode = "mid"
                label = bold("средний") + " (📍 зона, ⚙️ ВМ, 📥 статус/IP без сырых JSON)"
            elif flag in ("-low", "low"):
                dbg.mode = "low"
                label = bold("выкл") + " — как обычно"
            else:
                await notify.terminal_reply(
                    tid,
                    "Формат: "
                    + code("/debug")
                    + ", "
                    + code("/debug -mid")
                    + ", "
                    + code("/debug -low"),
                )
                return
        else:
            await notify.terminal_reply(
                tid,
                "Формат: "
                + code("/debug")
                + ", "
                + code("/debug -mid")
                + ", "
                + code("/debug -low"),
            )
            return
        warn = ""
        if cfg.topic_terminal is None:
            warn = (
                "\n⚠️ "
                + bold("TOPIC_ID_TERMINAL")
                + " не задан в .env — лог TWC в Telegram не отправится, пока не настроите топик."
            )
        await notify.terminal_reply(
            tid,
            "🔧 "
            + bold("Режим лога Timeweb API")
            + ": "
            + label
            + "\n"
            + "Сообщения идут в топик терминала (как и этот чат)."
            + warn,
        )
        return

    async def _acc_reply(html: str) -> None:
        await notify.terminal_reply(tid, html)

    if await handle_account_terminal_commands(cfg, db, text, _acc_reply):
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
        nets = load_networks(str(cfg.subnets_path))
        started = float(context.application.bot_data.get("started_at", time.time()))
        up = int(time.time() - started)
        body = "\n".join(
            [
                "🤖 " + bold("Sensability"),
                f"Версия: {code('1.0.0')}",
                f"Аптайм: {code(str(up))} с",
                f"Подсетей в ПНА: {code(str(len(nets)))}",
                f"Проверок IPv4 (сессия): {code(str(snap.ipv4_checks))}",
                f"Попаданий в ПНА (сессия): {code(str(snap.pool_hits))}",
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

    if low == "/drop":
        await notify.terminal_reply(tid, "⏳ " + bold("Останавливаю стек") + " — docker compose down…")

        async def job() -> None:
            await asyncio.sleep(2.0)
            if not compose_dir_ok(cfg):
                await notify.terminal_reply(tid, "❌ " + bold("Нет каталога compose") + f" ({esc(str(cfg.compose_dir))})")
                return
            code_, out, err = await compose_command(cfg, "down")
            await notify.terminal_reply(
                tid,
                f"{'✅' if code_ == 0 else '⚠️'} compose down exit {code_}\n<pre>{esc((out + err)[:3500])}</pre>",
            )

        asyncio.create_task(job())
        return

    if low == "/restart":
        await notify.terminal_reply(
            tid,
            "⏳ "
            + bold("Перезапуск стека")
            + " — <code>compose up -d --force-recreate</code> (без down из контейнера, иначе конфликт имён)…",
        )

        async def job() -> None:
            await asyncio.sleep(2.0)
            if not compose_dir_ok(cfg):
                await notify.terminal_reply(tid, "❌ compose dir missing")
                return
            c, o, e = await compose_command(
                cfg, "up", "-d", "--force-recreate", "--remove-orphans"
            )
            txt = (o + e)[:3500]
            await notify.terminal_reply(
                tid,
                f"{'✅' if c == 0 else '⚠️'} restart exit {c}\n<pre>{esc(txt)}</pre>",
            )

        asyncio.create_task(job())
        return

    if low == "/rebuild":
        await notify.terminal_reply(tid, "⏳ " + bold("Полная пересборка") + " — build + force-recreate…")

        async def job() -> None:
            await asyncio.sleep(2.0)
            if not compose_dir_ok(cfg):
                await notify.terminal_reply(tid, "❌ compose dir missing")
                return
            c1, o1, e1 = await compose_command(cfg, "build", "--no-cache")
            if c1 != 0:
                await notify.terminal_reply(
                    tid,
                    f"⚠️ build failed: {c1}\n<pre>{esc((o1 + e1)[:3500])}</pre>",
                )
                return
            c2, o2, e2 = await compose_command(
                cfg, "up", "-d", "--force-recreate", "--no-build", "--remove-orphans"
            )
            txt = (o2 + e2)[:3500]
            if c2 != 0:
                await notify.terminal_reply(
                    tid,
                    f"⚠️ up failed: {c2}\n<pre>{esc(txt)}</pre>",
                )
                return
            await notify.terminal_reply(tid, "✅ " + bold("Пересборка завершена"))

        asyncio.create_task(job())
        return

    await notify.terminal_reply(tid, "Неизвестная команда. /help")


async def handle_accountverify(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    cfg, db, twc, stats, notify, _orch = _ctx(context.application)
    tid = update.message.message_thread_id if update.message else None

    async def _vreply(html: str) -> None:
        await notify.accountverify_reply(tid, html)

    if await handle_account_terminal_commands(cfg, db, text, _vreply):
        return

    m = RE_ACCOUNT_ADD.match(text)
    if m:
        name, key = _split_name_key(m.group(1))
        if not name or not key:
            await notify.accountverify_reply(tid, "Формат: " + code("/account_add имя:apiKey"))
            return
        try:
            fin = await twc.get_finances(key)
            bal, cur = finances_balance_rubles(fin)
        except Exception as ex:
            await notify.accountverify_reply(tid, f"❌ API ключ не подошёл: {esc(str(ex)[:400])}")
            return
        await db.add_account(name, key)
        row = await sync_account(db, twc, cfg, name)
        em = row.acc_email if row else None
        lg = row.acc_login if row else None
        await notify.accountverify_reply(
            tid,
            "\n".join(
                [
                    "✅ " + bold("Аккаунт подключён"),
                    "┈ " + bold("Имя в боте") + f" {code(name)}",
                    "┈ " + bold("Email") + f" {code(em or '—')}",
                    "┈ " + bold("Login") + f" {code(lg or '—')}",
                    "┈ " + bold("Баланс") + f" {code(str(bal))} {esc(cur or '')}",
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
        now = time.time()
        left_day = "—"
        if row.limited_by_day and row.limited_by_day_ts:
            left = max(0, int(row.limited_by_day_ts + 86400 - now))
            left_day = f"{left // 3600}ч {(left % 3600) // 60}м"
        left_m = "—"
        if row.limited_by_month and row.limited_by_month_ts:
            lm = max(0, int(row.limited_by_month_ts + 3600 - now))
            left_m = f"{lm // 60}м {lm % 60}с"
        bal_s = "—" if row.balance_cached is None else f"{row.balance_cached:g}"
        mode_ip = (
            "📡 плавающий IPv4 (без ВМ)"
            if account_prefers_floating_ip_probe(row)
            else "🖥 облачная ВМ"
        )
        body = "\n".join(
            [
                "🪪 " + bold("Карточка аккаунта") + f" {code(name)}",
                "┈ " + bold("Email") + f": {code(row.acc_email or '—')}",
                "┈ " + bold("Login") + f": {code(row.acc_login or '—')}",
                "┈ " + bold("Баланс") + f": {code(bal_s)} {esc(row.currency or '')}",
                "┈ " + bold("Режим перебора") + f": {mode_ip}",
                "┈ " + bold("В подборе") + f": {'✅ да' if row.brute_enabled else '❌ нет'}",
                "┈ " + bold("Лимит баланса") + f": {'⚠️ да' if row.limited_by_balance else '✅ нет'}",
                "┈ " + bold("Лимит месяца") + f": {'⚠️ да' if row.limited_by_month else '✅ нет'} (~{left_m})",
                "┈ " + bold("Лимит суток") + f": {'⚠️ да' if row.limited_by_day else '✅ нет'} (~{left_day})",
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
                code("/account_add имя:ключ"),
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
