from __future__ import annotations

import json
import re
from typing import Any, Literal

from sensability.tg_format import bold, code, esc

TwcDebugMode = Literal["low", "mid", "full"]

_MAX_FULL = 7500
_MAX_MSG = 3900


class TwcApiDebugController:
    """Режим логирования TWC HTTP в топик терминала: low (выкл), mid, full."""

    __slots__ = ("mode",)

    def __init__(self, mode: TwcDebugMode = "low") -> None:
        self.mode: TwcDebugMode = mode


def _truncate(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    return s[: limit - 40] + "\n\n… " + esc("усечено")


def _chunk_messages(html: str) -> list[str]:
    if len(html) <= _MAX_MSG:
        return [html]
    parts: list[str] = []
    i = 0
    while i < len(html):
        parts.append(html[i : i + _MAX_MSG])
        i += _MAX_MSG
    return parts


def _full_request_html(method: str, path: str, json_body: Any) -> str:
    lines = [f"{method} {path}", "Authorization: Bearer <скрыто>"]
    if json_body is not None:
        try:
            raw = json.dumps(json_body, ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            raw = repr(json_body)
    else:
        raw = "(без JSON-тела)"
    lines.append(raw)
    inner = _truncate("\n".join(lines), _MAX_FULL)
    block = "<blockquote><pre>" + esc(inner) + "</pre></blockquote>"
    return bold("TWC") + " " + code(f"{method} {path}") + "\n📤 " + bold("Запрос") + "\n" + block


def _full_response_html(method: str, path: str, status: int, text: str, parsed: Any, ok: bool) -> str:
    if parsed is not None and isinstance(parsed, (dict, list)):
        try:
            inner = json.dumps(parsed, ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            inner = text or ""
    else:
        inner = text or ""
    inner = _truncate(inner, _MAX_FULL)
    block = "<blockquote><pre>" + esc(inner) + "</pre></blockquote>"
    st = "✅" if ok else "❌"
    return (
        bold("TWC")
        + " "
        + code(f"{method} {path}")
        + "\n"
        + st
        + " "
        + bold("Ответ")
        + " "
        + code(str(status))
        + "\n"
        + block
    )


def _mid_request_lines(method: str, path: str, json_body: Any) -> list[str]:
    out: list[str] = [f"📤 {bold('Запрос')} {code(method + ' ' + path)}"]
    p = path
    if isinstance(json_body, dict) and method == "POST" and p.rstrip("/").endswith("/servers"):
        z = json_body.get("availability_zone")
        out.append("📍 " + bold("Зона") + ": " + code(str(z) if z else "по умолчанию"))
        out.append(
            "⚙️ "
            + bold("ВМ")
            + ": "
            + code("preset_id=" + str(json_body.get("preset_id", "—")))
            + " · "
            + code("os_id=" + str(json_body.get("os_id", "—")))
            + " · "
            + code("bw=" + str(json_body.get("bandwidth", "—")))
        )
        nm = json_body.get("name")
        if nm:
            out.append("🖥 " + bold("Имя") + ": " + code(str(nm)))
        out.append("🛡 " + code("ddos=" + str(json_body.get("is_ddos_guard"))) + " · " + code("local_net=" + str(json_body.get("is_local_network"))))
    elif isinstance(json_body, dict) and json_body and method != "GET":
        out.append("📦 " + bold("Тело") + ": " + code(_truncate(json.dumps(json_body, ensure_ascii=False), 400)))
    elif "finances" in p:
        out.append("💰 " + bold("Баланс / финансы"))
    elif "account/status" in p:
        out.append("👤 " + bold("Статус аккаунта"))
    elif "notification-settings" in p:
        out.append("🔔 " + bold("Настройки уведомлений"))
    elif re.search(r"/servers/\d+/ips\b", p):
        out.append("🌐 " + bold("Список IP сервера"))
    elif re.search(r"/servers/\d+\s*$", p) or (re.search(r"/servers/\d+$", p) and method == "GET"):
        out.append("🖥 " + bold("Карточка сервера"))
    elif re.search(r"/servers/\d+/shutdown", p):
        out.append("⏻ " + bold("Выключение сервера"))
    elif method == "DELETE" and re.search(r"/servers/\d+$", p):
        out.append("🗑 " + bold("Удаление сервера"))
    return out


def _mid_response_lines(method: str, path: str, status: int, parsed: Any, ok: bool, text: str) -> list[str]:
    st = "✅" if ok else "❌"
    out: list[str] = [f"📥 {bold('Ответ')} {code(str(status))} {st}"]
    if not isinstance(parsed, dict):
        if not ok and text:
            out.append("⚠️ " + code(_truncate(text, 500)))
        return out
    srv = parsed.get("server")
    if isinstance(srv, dict):
        out.append("🖥 " + bold("Сервер") + ": " + code("id=" + str(srv.get("id", "—"))))
        out.append(
            "📍 "
            + bold("Локация")
            + ": "
            + code(str(srv.get("availability_zone") or srv.get("location_zone") or "—"))
        )
        stt = srv.get("status") or srv.get("state")
        if stt:
            out.append("📊 " + bold("Статус") + ": " + code(str(stt)))
        preset = srv.get("preset_id")
        os_id = srv.get("os_id")
        if preset is not None or os_id is not None:
            out.append(
                "⚙️ "
                + bold("Тариф/ОС")
                + ": "
                + code("preset_id=" + str(preset if preset is not None else "—"))
                + " · "
                + code("os_id=" + str(os_id if os_id is not None else "—"))
            )
        conf = srv.get("configuration")
        if isinstance(conf, dict):
            cpu = conf.get("cpu")
            ram = conf.get("ram")
            disk = conf.get("disk")
            if any(x is not None for x in (cpu, ram, disk)):
                out.append(
                    "💾 "
                    + bold("Ресурсы")
                    + ": "
                    + code(f"cpu={cpu}, ram_mb={ram}, disk_mb={disk}")
                )
    fin = parsed.get("finances")
    if isinstance(fin, dict):
        bal = fin.get("balance")
        cur = fin.get("currency")
        out.append("💰 " + bold("Баланс") + ": " + code(str(bal)) + " " + esc(str(cur or "")))
    ips = parsed.get("server_ips") or parsed.get("ips")
    if isinstance(ips, list) and ips:
        addrs: list[str] = []
        for it in ips[:12]:
            if isinstance(it, dict):
                a = it.get("ip") or it.get("address")
                if a:
                    addrs.append(str(a))
        if addrs:
            out.append("🌐 " + bold("IP") + ": " + code(", ".join(addrs)))
    if not ok:
        msg = parsed.get("message") or parsed.get("error") or parsed.get("error_code")
        if msg:
            out.append("⚠️ " + bold("Сообщение") + ": " + code(str(msg)[:800]))
    return out


def build_request_debug_html(mode: TwcDebugMode, method: str, path: str, json_body: Any) -> list[str]:
    if mode == "low":
        return []
    if mode == "full":
        return _chunk_messages(_full_request_html(method, path, json_body))
    lines = _mid_request_lines(method, path, json_body)
    return _chunk_messages("\n".join(lines))


def build_response_debug_html(
    mode: TwcDebugMode,
    method: str,
    path: str,
    status: int,
    text: str,
    parsed: Any,
    ok: bool,
) -> list[str]:
    if mode == "low":
        return []
    if mode == "full":
        return _chunk_messages(_full_response_html(method, path, status, text, parsed, ok))
    lines = _mid_response_lines(method, path, status, parsed, ok, text)
    return _chunk_messages("\n".join(lines))
