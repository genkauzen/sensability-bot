from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from telegram.constants import ParseMode

if TYPE_CHECKING:
    from telegram import Bot

    from sensability.config import Config

log = logging.getLogger("sensability.notify")


class TelegramNotify:
    def __init__(self, bot: Bot, cfg: Config) -> None:
        self._bot = bot
        self._cfg = cfg

    async def _send(self, thread_id: int | None, text: str) -> None:
        if not thread_id or not self._cfg.group_id:
            log.debug("skip send (no topic or group): %s", text[:80])
            return
        try:
            await self._bot.send_message(
                chat_id=self._cfg.group_id,
                text=text,
                message_thread_id=thread_id,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
        except Exception as e:
            log.warning("telegram send failed: %s", e)

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
