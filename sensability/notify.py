from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from telegram.constants import ParseMode

if TYPE_CHECKING:
    from telegram import Bot

    from sensability.config import Config
    from sensability.db import Database

log = logging.getLogger("sensability.notify")


class TelegramNotify:
    def __init__(self, bot: Bot, cfg: Config, db: Database | None = None) -> None:
        self._bot = bot
        self._cfg = cfg
        self._db = db

    def _should_track_thread(self, thread_id: int | None) -> bool:
        if thread_id is None:
            return False
        for t in (
            self._cfg.topic_live,
            self._cfg.topic_terminal,
            self._cfg.topic_logs,
        ):
            if t is not None and thread_id == t:
                return True
        return False

    async def _send(self, thread_id: int | None, text: str) -> None:
        if not thread_id or not self._cfg.group_id:
            log.debug("skip send (no topic or group): %s", text[:80])
            return
        try:
            msg = await self._bot.send_message(
                chat_id=self._cfg.group_id,
                text=text,
                message_thread_id=thread_id,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            if self._db and self._should_track_thread(thread_id):
                await self._db.remember_bot_outbox(thread_id, msg.message_id)
        except Exception as e:
            log.warning("telegram send failed: %s", e)

    async def delete_tracked_in_threads(self, thread_ids: list[int]) -> int:
        """Удаляет сообщения бота, id которых сохранены в bot_outbox (только эти топики)."""
        if not self._db or not self._cfg.group_id or not thread_ids:
            return 0
        rows = await self._db.list_outbox_for_threads(thread_ids)
        n = 0
        for _tid, mid in rows:
            try:
                await self._bot.delete_message(chat_id=self._cfg.group_id, message_id=mid)
                n += 1
            except Exception:
                pass
        await self._db.clear_outbox_threads(thread_ids)
        return n

    async def logs(self, html: str) -> None:
        await self._send(self._cfg.topic_logs, html)

    async def live(self, html: str) -> None:
        await self._send(self._cfg.topic_live, html)

    async def totalresult(self, html: str) -> None:
        await self._send(self._cfg.topic_totalresult, html)

    async def updaywork(self, html: str) -> None:
        await self._send(self._cfg.topic_updaywork, html)

    async def terminal_reply(self, thread_id: int | None, html: str) -> None:
        await self._send(thread_id, html)

    async def accountverify_reply(self, thread_id: int | None, html: str) -> None:
        await self._send(thread_id, html)
