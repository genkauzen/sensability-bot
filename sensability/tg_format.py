from __future__ import annotations

import html


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def code(s: str) -> str:
    return f"<code>{esc(s)}</code>"


def bold(s: str) -> str:
    return f"<b>{esc(s)}</b>"


def spoiler(s: str) -> str:
    return f'<tg-spoiler>{esc(s)}</tg-spoiler>'


def spoiler_code(s: str) -> str:
    return f"<tg-spoiler><code>{esc(s)}</code></tg-spoiler>"
