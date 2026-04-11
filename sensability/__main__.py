from __future__ import annotations

import logging
import os
import sys
import time

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, Defaults, MessageHandler, filters

from sensability.brute_worker import BruteOrchestrator
from sensability.config import Config, load_config
from sensability.db import Database, db_path
from sensability.handlers import on_message, schedule_daily
from sensability.ip_pool import load_networks
from sensability.notify import TelegramNotify
from sensability.stats import StatsCollector
from sensability.tg_format import bold, esc
from sensability.twc_client import TimewebClient
from sensability.twc_debug import TwcApiDebugController

log = logging.getLogger("sensability")


async def post_init(application: Application) -> None:
    cfg: Config = application.bot_data["cfg"]
    db: Database = application.bot_data["db"]
    orch: BruteOrchestrator = application.bot_data["orchestrator"]
    notify: TelegramNotify = application.bot_data["notify"]
    await db.connect()
    orch.start()
    schedule_daily(application, cfg)
    await notify.logs("✅ " + bold("Sensability запущен") + f"\nГруппа: {esc(str(cfg.group_id))}")


async def post_shutdown(application: Application) -> None:
    orch: BruteOrchestrator = application.bot_data["orchestrator"]
    twc: TimewebClient = application.bot_data["twc"]
    db: Database = application.bot_data["db"]
    notify: TelegramNotify = application.bot_data["notify"]
    await orch.stop()
    await twc.aclose()
    await db.close()
    try:
        await notify.logs("⏹ " + bold("Sensability остановлен"))
    except Exception:
        pass


def main() -> None:
    cfg = load_config()
    if not cfg.bot_token:
        print("BOT_TOKEN обязателен", file=sys.stderr)
        sys.exit(1)
    if not cfg.group_id:
        print("GROUP_ID обязателен", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.DEBUG if cfg.full_logs else logging.INFO,
    )

    try:
        load_networks(str(cfg.subnets_path))
    except FileNotFoundError:
        print(f"Файл подсетей не найден: {cfg.subnets_path}", file=sys.stderr)
        sys.exit(1)

    proxy = cfg.tg_proxy_url if cfg.tg_proxy_use and cfg.tg_proxy_url else None
    builder = (
        Application.builder()
        .token(cfg.bot_token)
        .defaults(Defaults(parse_mode=ParseMode.HTML, disable_web_page_preview=True))
        .post_init(post_init)
        .post_shutdown(post_shutdown)
    )
    if proxy:
        builder = builder.proxy(proxy).get_updates_proxy(proxy)

    application = builder.build()

    twc_proxy = cfg.twc_proxy_url if cfg.twc_proxy_use and cfg.twc_proxy_url else None
    twc_debug = TwcApiDebugController()
    db = Database(db_path(cfg))
    stats = StatsCollector()
    notify = TelegramNotify(application.bot, cfg)

    async def twc_debug_emit(html: str) -> None:
        tid = cfg.topic_terminal
        if tid is None:
            return
        await notify.terminal_reply(tid, html)

    twc = TimewebClient(twc_proxy, debug_ctrl=twc_debug, debug_emit=twc_debug_emit)
    nets = load_networks(str(cfg.subnets_path))
    orchestrator = BruteOrchestrator(cfg, db, twc, stats, notify, nets)

    tz = os.getenv("TZ", "Europe/Moscow")
    application.bot_data.update(
        cfg=cfg,
        db=db,
        twc=twc,
        twc_debug=twc_debug,
        stats=stats,
        notify=notify,
        orchestrator=orchestrator,
        started_at=time.time(),
        tz=tz,
    )

    application.add_handler(MessageHandler(filters.Chat(chat_id=cfg.group_id) & filters.TEXT, on_message))

    log.info("Starting polling for group %s", cfg.group_id)
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
