from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, time as dtime
from typing import TYPE_CHECKING, Any

from telegram import Update
from telegram.ext import ContextTypes
from zoneinfo import ZoneInfo

from sensability.account_sync import sync_account
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
    cfg, db, twc, stats, notify, _orch = _ctx(context.application)
    tid = update.message.message_thread_id if update.message else None
    low = text.lower().strip()

    if low in ("/help", "/commands", "commands", "help"):
        body = "\n".join(
            [
                bold("Sensability — терминал"),
                "/status — состояние бота",
                "/modules — активные компоненты",
                "/drop — docker compose down (пауза)",
                "/restart — down + up",
                "/rebuild — down + build --no-cache + up",
                "/help — этот список",
            ]
        )
        await notify.terminal_reply(tid, body)
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
            ]
        )
        await notify.terminal_reply(tid, body)
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
        await notify.terminal_reply(tid, "⏳ " + bold("Перезапуск стека") + " — down && up -d…")

        async def job() -> None:
            await asyncio.sleep(2.0)
            if not compose_dir_ok(cfg):
                await notify.terminal_reply(tid, "❌ compose dir missing")
                return
            c1, o1, e1 = await compose_command(cfg, "down")
            c2, o2, e2 = await compose_command(cfg, "up", "-d")
            txt = (o1 + e1 + o2 + e2)[:3500]
            await notify.terminal_reply(tid, f"restart: {c1}/{c2}\n<pre>{esc(txt)}</pre>")

        asyncio.create_task(job())
        return

    if low == "/rebuild":
        await notify.terminal_reply(tid, "⏳ " + bold("Полная пересборка") + " — может занять несколько минут…")

        async def job() -> None:
            await asyncio.sleep(2.0)
            if not compose_dir_ok(cfg):
                await notify.terminal_reply(tid, "❌ compose dir missing")
                return
            for args in (("down",), ("build", "--no-cache"), ("up", "-d")):
                c, o, e = await compose_command(cfg, *args)
                if c != 0:
                    await notify.terminal_reply(
                        tid,
                        f"⚠️ step failed {args}: {c}\n<pre>{esc((o + e)[:3500])}</pre>",
                    )
                    return
            await notify.terminal_reply(tid, "✅ " + bold("Пересборка завершена"))

        asyncio.create_task(job())
        return

    await notify.terminal_reply(tid, "Неизвестная команда. /help")


async def handle_accountverify(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    cfg, db, twc, stats, notify, _orch = _ctx(context.application)
    tid = update.message.message_thread_id if update.message else None

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
        await sync_account(db, twc, cfg, name)
        await notify.accountverify_reply(
            tid,
            "✅ "
            + bold("Аккаунт добавлен")
            + f"\nИмя: {code(name)}\nБаланс: {code(str(bal))} {esc(cur or '')}",
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
        body = "\n".join(
            [
                bold("Аккаунт") + f" {code(name)}",
                f"login: {code(row.acc_login or '—')}",
                f"email: {code(row.acc_email or '—')}",
                f"limitedByBalance: {code(str(row.limited_by_balance))}",
                f"limitedByMonthBalanceError: {code(str(row.limited_by_month))} (осталось ~{left_m})",
                f"limitedByPerDay: {code(str(row.limited_by_day))}",
                f"limitedByPerDay осталось: {code(left_day)}",
                f"В пуле перебора: {code(str(row.brute_enabled))}",
                f"Баланс (кэш): {code(str(row.balance_cached))} {esc(row.currency or '')}",
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
        "Команды: "
        + code("/account_add имя:ключ")
        + ", "
        + code("/account_info имя")
        + ", …",
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
