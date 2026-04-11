from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import TYPE_CHECKING

from sensability.account_sync import (
    account_eligible_for_brute,
    account_prefers_floating_ip_probe,
    sync_account,
)
from sensability.config import Config
from sensability.db import AccountRow, Database
from sensability.ip_pool import ipv4_in_any_potential, ipv4_in_pool
from sensability.notify import TelegramNotify
from sensability.stats import StatsCollector
from sensability.tg_format import bold, code, esc, spoiler_code
from sensability.twc_constants import (
    TWC_BANDWIDTH,
    TWC_FLOAT_IP_ZONES,
    TWC_OS_ID,
    TWC_PRESET_ID,
)
from sensability.twc_client import (
    TimewebApiError,
    extract_ipv4_from_floating_record,
    extract_ipv4_from_server,
    extract_public_ipv4s,
    floating_ip_record_from_response,
    is_floating_ip_not_found,
    is_server_not_found,
    looks_like_daily_limit_error,
    looks_like_month_balance_error,
    parse_error_message,
)

if TYPE_CHECKING:
    from sensability.twc_client import TimewebClient

log = logging.getLogger("sensability.brute")

POLL_INTERVAL = 3.0
POLL_ATTEMPTS = 45
NOTFOUND_GIVEUP = 1


class BruteOrchestrator:
    def __init__(
        self,
        cfg: Config,
        db: Database,
        twc: TimewebClient,
        stats: StatsCollector,
        notify: TelegramNotify,
        networks: tuple,
        potential_networks: tuple,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.twc = twc
        self.stats = stats
        self.notify = notify
        self._networks = networks
        self._potential_networks = potential_networks
        self._sem = asyncio.Semaphore(cfg.twc_atmoment_acc)
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._stop = asyncio.Event()
        self._supervisor_task: asyncio.Task[None] | None = None
        self._brute_paused = False

    def set_brute_paused(self, paused: bool) -> None:
        self._brute_paused = paused

    def is_brute_paused(self) -> bool:
        return self._brute_paused

    def _build_create_body(self, vm_name: str) -> dict:
        zone = self.cfg.twc_vm_region.strip()
        body: dict = {
            "name": vm_name,
            "preset_id": TWC_PRESET_ID,
            "os_id": TWC_OS_ID,
            "bandwidth": TWC_BANDWIDTH,
            "is_ddos_guard": False,
            "is_local_network": False,
            "comment": "sensability",
        }
        # Конкретная availability_zone (spb-3, msk-1, …) API принимает не у всех аккаунтов
        # (нужен мультизональный доступ); иначе 400 location_zone … is not valid.
        if zone:
            body["availability_zone"] = zone
        return body

    def _ip_live_extra_lines(self, pub_ip: str | None) -> list[str]:
        if not pub_ip:
            return [
                "┈ " + bold("Пул ПНА") + ": —",
                "┈ " + bold("Потенциал (±2 к октетам)") + ": —",
            ]
        in_pool = ipv4_in_pool(pub_ip, self._networks)
        pot = (
            ipv4_in_any_potential(pub_ip, self._potential_networks, delta=2)
            if self._potential_networks
            else False
        )
        pl = "✅ в ПНА" if in_pool else "❌ вне ПНА"
        pt = "✅ рядом с потенциальной подсетью" if pot else "— вне потенциала"
        return [
            "┈ " + bold("Пул ПНА") + f": {pl}",
            "┈ " + bold("Потенциал") + f": {pt}",
        ]

    async def _try_cleanup_orphan_vm(self, name: str, row: AccountRow, vm_name: str) -> bool:
        try:
            lst = await self.twc.list_servers(row.api_key)
            for s in lst.get("servers") or []:
                if not isinstance(s, dict):
                    continue
                if str(s.get("name") or "") != vm_name:
                    continue
                sid = int(s.get("id") or 0)
                if not sid:
                    continue
                try:
                    await self.twc.delete_server(row.api_key, sid)
                except TimewebApiError:
                    pass
                await self.db.patch_account(
                    name,
                    {"limited_by_month": 1, "limited_by_month_ts": time.time()},
                )
                await self.db.log_event(
                    "orphan_unpaid_vm",
                    name,
                    {"server_id": sid, "vm_name": vm_name},
                )
                await self.stats.add_month_err()
                return True
        except Exception:
            log.exception("orphan vm cleanup %s", name)
        return False

    async def run_once_account(self, name: str) -> None:
        if self._brute_paused:
            return
        async with self._sem:
            if self._brute_paused:
                return
            row = await sync_account(self.db, self.twc, self.cfg, name)
            if not row:
                return
            if not account_eligible_for_brute(row, self.cfg):
                return

            if account_prefers_floating_ip_probe(row):
                await self._run_brute_floating_ip(name, row)
            else:
                await self._run_brute_vm(name, row)

    async def _run_brute_vm(self, name: str, row: AccountRow) -> None:
        await self.stats.track_account(name, row.balance_cached)
        vm_name = f"{self.cfg.twc_vm_name}-{row.name}-{uuid.uuid4().hex[:8]}"
        body = self._build_create_body(vm_name)

        if self.cfg.full_logs:
            await self.notify.logs(f"{bold('TWC')} <code>POST /api/v1/servers</code> · {esc(name)}")

        try:
            data = await self.twc.create_server(row.api_key, body)
        except TimewebApiError as e:
            msg = parse_error_message(e)
            if self.cfg.full_logs:
                await self.notify.logs(f"{bold('TWC ошибка')} {e.status}: {esc(msg[:800])}")
            if looks_like_month_balance_error(msg):
                await self.db.patch_account(
                    name,
                    {
                        "limited_by_month": 1,
                        "limited_by_month_ts": time.time(),
                    },
                )
                await self.stats.add_month_err()
                await self.db.log_event("month_balance_error", name, {"message": msg[:2000]})
                return
            if await self._try_cleanup_orphan_vm(name, row, vm_name):
                return
            await self.stats.add_vm_fail()
            await self.db.log_event("create_fail", name, {"status": e.status, "msg": msg[:2000]})
            return

        await self.stats.add_vm_ok()
        server = data.get("server") if isinstance(data, dict) else None
        if not isinstance(server, dict):
            await self.stats.add_vm_fail()
            return
        sid = server.get("id")
        if sid is None:
            await self.stats.add_vm_fail()
            return
        server_id = int(sid)
        root_pass = str(server.get("root_pass") or "")
        region = str(server.get("availability_zone") or self.cfg.twc_vm_region or "—")

        for attempt in range(3):
            try:
                await asyncio.sleep(3.0 if attempt else 2.0)
                await self.twc.add_server_ipv4(row.api_key, server_id)
                break
            except TimewebApiError as ex:
                if attempt >= 2:
                    await self.notify.logs(
                        "⚠️ "
                        + bold("POST /servers/…/ips (ipv4)")
                        + f" {code(name)} после 3 попыток: {esc(parse_error_message(ex)[:500])}"
                    )
                elif self.cfg.full_logs:
                    await self.notify.logs(
                        f"{bold('add_server_ipv4')} попытка {attempt + 2}/3 {esc(name)}: "
                        f"{esc(parse_error_message(ex)[:300])}"
                    )

        pub_ip: str | None = None
        notfound_streak = 0
        for _ in range(POLL_ATTEMPTS):
            if self._stop.is_set() or self._brute_paused:
                break
            await asyncio.sleep(POLL_INTERVAL)
            await self.stats.add_ipv4_check()
            try:
                ips_d = await self.twc.get_server_ips(row.api_key, server_id)
                ips = extract_public_ipv4s(ips_d)
                if not ips:
                    srv = await self.twc.get_server(row.api_key, server_id)
                    s = srv.get("server") if isinstance(srv, dict) else None
                    if isinstance(s, dict):
                        ips = extract_ipv4_from_server(s)
                for ip in ips:
                    if ip.count(".") == 3:
                        pub_ip = ip
                        break
            except TimewebApiError as ex:
                pmsg = parse_error_message(ex)
                if looks_like_daily_limit_error(pmsg) or ex.status == 429:
                    await self.db.patch_account(
                        name,
                        {"limited_by_day": 1, "limited_by_day_ts": time.time()},
                    )
                    await self.stats.add_cooldown24()
                    await self.db.log_event("daily_limit_api", name, {"msg": pmsg[:800]})
                    try:
                        await self.twc.delete_server(row.api_key, server_id)
                    except Exception:
                        pass
                    return
                if is_server_not_found(ex):
                    notfound_streak += 1
                    if self.cfg.full_logs:
                        await self.notify.logs(
                            f"{bold('poll ip')} {esc(name)}: сервер не найден ({notfound_streak}/{NOTFOUND_GIVEUP})"
                        )
                    if notfound_streak >= NOTFOUND_GIVEUP:
                        await self.notify.live(
                            "\n".join(
                                [
                                    "🖥 " + bold("Live — облачная ВМ"),
                                    "┈ " + bold("Аккаунт") + f" {code(name)}",
                                    "┈ " + bold("ВМ") + f" {code(vm_name)}",
                                    "┈ " + bold("Регион") + f" {code(region)}",
                                    "┈ " + bold("IPv4") + f" {code('— (ВМ удалена вручную)')}",
                                ]
                            )
                        )
                        await self.notify.logs(
                            f"⚠️ {bold('ВМ снята с учёта')} {code(name)} id {code(str(server_id))} — "
                            f"нет в API после ручного удаления."
                        )
                        await self.db.log_event(
                            "vm_registry_drop",
                            name,
                            {"server_id": server_id, "reason": "404"},
                        )
                        return
                elif self.cfg.full_logs:
                    await self.notify.logs(f"{bold('poll ip')} {esc(name)}: {esc(str(ex)[:200])}")
            except Exception as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('poll ip')} {esc(name)}: {esc(str(ex)[:200])}")
            if pub_ip:
                break

        live_vm = [
            "🖥 " + bold("Live — облачная ВМ"),
            "┈ " + bold("Аккаунт") + f" {code(name)}",
            "┈ " + bold("ВМ") + f" {code(vm_name)}",
            "┈ " + bold("Регион") + f" {code(region)}",
            "┈ " + bold("IPv4") + f" {code(pub_ip or '—')}",
        ]
        live_vm.extend(self._ip_live_extra_lines(pub_ip))
        await self.notify.live("\n".join(live_vm))

        if not pub_ip:
            if notfound_streak >= NOTFOUND_GIVEUP:
                return
            await self.db.patch_account(
                name,
                {
                    "limited_by_day": 1,
                    "limited_by_day_ts": time.time(),
                },
            )
            await self.stats.add_cooldown24()
            try:
                await self.twc.delete_server(row.api_key, server_id)
            except TimewebApiError as ex:
                if not is_server_not_found(ex):
                    await self.notify.logs(f"{bold('Удаление ВМ')} {esc(str(ex)[:300])}")
            except Exception as ex:
                await self.notify.logs(f"{bold('Удаление ВМ')} {esc(str(ex)[:300])}")
            await self.db.log_event("no_ipv4", name, {"server_id": server_id})
            return

        if ipv4_in_pool(pub_ip, self._networks):
            await self.stats.add_pool_hit()
            await self.db.patch_account(name, {"brute_enabled": 0})
            await self.db.append_whitelist_server(name, server_id)
            await self.db.log_event("pool_hit", name, {"ip": pub_ip, "server_id": server_id})
            login_line = f"root@{pub_ip}"
            pass_block = spoiler_code(root_pass) if root_pass else code("—")
            msg = "\n".join(
                [
                    "🎯 " + bold("Попадание в ПНА"),
                    "🖥 " + bold("Режим") + " облачная ВМ",
                    "┈ " + bold("Аккаунт") + f" {code(name)}",
                    "┈ " + bold("SSH login") + f" {code(login_line)}",
                    "┈ " + bold("Пароль root") + f" {pass_block}",
                    "┈ " + bold("ВМ id") + f" {code(str(server_id))} — в белом списке, авто-выключение по таймеру",
                ]
            )
            await self.notify.totalresult(msg)
            asyncio.create_task(
                self._shutdown_later(row.api_key, server_id, vm_name, name),
                name=f"shutdown-{server_id}",
            )
        else:
            await self.stats.add_vm_deleted_no_pool()
            try:
                await self.twc.delete_server(row.api_key, server_id)
            except TimewebApiError as ex:
                if not is_server_not_found(ex):
                    await self.notify.logs(f"{bold('Удаление ВМ')} {esc(str(ex)[:300])}")
            except Exception as ex:
                await self.notify.logs(f"{bold('Удаление ВМ')} {esc(str(ex)[:300])}")
            await self.db.log_event("ip_not_in_pool", name, {"ip": pub_ip, "server_id": server_id})

    async def _run_brute_floating_ip(self, name: str, row: AccountRow) -> None:
        await self.stats.track_account(name, row.balance_cached)
        if self.cfg.full_logs:
            await self.notify.logs(f"{bold('TWC')} плавающий IP · {esc(name)} (баланс выше порога)")

        data: dict | None = None
        zone_used = ""
        for zone in TWC_FLOAT_IP_ZONES:
            body = {"is_ddos_guard": False, "availability_zone": zone}
            try:
                data = await self.twc.create_floating_ip(row.api_key, body)
                zone_used = zone
                break
            except TimewebApiError as e:
                msg = parse_error_message(e)
                if self.cfg.full_logs:
                    await self.notify.logs(
                        f"{bold('TWC')} <code>POST /api/v1/floating-ips</code> {code(zone)}: "
                        f"{esc(msg[:500])}"
                    )
                if looks_like_month_balance_error(msg):
                    await self.db.patch_account(
                        name,
                        {
                            "limited_by_month": 1,
                            "limited_by_month_ts": time.time(),
                        },
                    )
                    await self.stats.add_month_err()
                    await self.db.log_event("month_balance_error", name, {"message": msg[:2000]})
                    return
                continue

        if not data:
            await self.stats.add_vm_fail()
            await self.db.log_event("float_ip_create_fail", name, {"zones": list(TWC_FLOAT_IP_ZONES)})
            return

        await self.stats.add_float_ok()
        fi = floating_ip_record_from_response(data)
        if not fi:
            await self.stats.add_vm_fail()
            await self.db.log_event("float_ip_bad_response", name, {})
            return
        fid = str(fi.get("id") or "").strip()
        if not fid:
            await self.stats.add_vm_fail()
            return

        pub_ip: str | None = extract_ipv4_from_floating_record(fi)
        notfound_streak = 0
        for _ in range(POLL_ATTEMPTS):
            if self._stop.is_set() or self._brute_paused:
                break
            if pub_ip:
                break
            await asyncio.sleep(POLL_INTERVAL)
            await self.stats.add_ipv4_check()
            try:
                pl = await self.twc.get_floating_ip(row.api_key, fid)
                inner = floating_ip_record_from_response(pl) if isinstance(pl, dict) else None
                if isinstance(inner, dict):
                    pub_ip = extract_ipv4_from_floating_record(inner)
            except TimewebApiError as ex:
                pmsg = parse_error_message(ex)
                if looks_like_daily_limit_error(pmsg) or ex.status == 429:
                    await self.db.patch_account(
                        name,
                        {"limited_by_day": 1, "limited_by_day_ts": time.time()},
                    )
                    await self.stats.add_cooldown24()
                    await self.db.log_event("daily_limit_float", name, {"msg": pmsg[:800]})
                    try:
                        await self.twc.delete_floating_ip(row.api_key, fid)
                    except Exception:
                        pass
                    return
                if is_floating_ip_not_found(ex):
                    notfound_streak += 1
                    if notfound_streak >= NOTFOUND_GIVEUP:
                        await self.notify.live(
                            "\n".join(
                                [
                                    "📡 " + bold("Live — плавающий IPv4"),
                                    "┈ " + bold("Аккаунт") + f" {code(name)}",
                                    "┈ " + bold("Зона") + f" {code(zone_used)}",
                                    "┈ " + bold("IPv4-Address") + f" {code('— (ресурс удалён)')}",
                                ]
                            )
                        )
                        await self.db.log_event(
                            "float_ip_registry_drop",
                            name,
                            {"floating_ip_id": fid, "reason": "404"},
                        )
                        return
                elif self.cfg.full_logs:
                    await self.notify.logs(f"{bold('poll float ip')} {esc(name)}: {esc(str(ex)[:200])}")
            except Exception as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('poll float ip')} {esc(name)}: {esc(str(ex)[:200])}")

        live_f = [
            "📡 " + bold("Live — плавающий публичный IPv4"),
            "┈ " + bold("Аккаунт") + f" {code(name)}",
            "┈ " + bold("Зона доступности") + f" {code(zone_used)}",
            "┈ " + bold("📡IPv4-Address:") + f" {code(pub_ip or '—')}",
        ]
        live_f.extend(self._ip_live_extra_lines(pub_ip))
        await self.notify.live("\n".join(live_f))

        if not pub_ip:
            if notfound_streak >= NOTFOUND_GIVEUP:
                return
            await self.db.patch_account(
                name,
                {"limited_by_day": 1, "limited_by_day_ts": time.time()},
            )
            await self.stats.add_cooldown24()
            try:
                await self.twc.delete_floating_ip(row.api_key, fid)
            except TimewebApiError as ex:
                if not is_floating_ip_not_found(ex):
                    await self.notify.logs(f"{bold('Удаление float IP')} {esc(str(ex)[:300])}")
            except Exception as ex:
                await self.notify.logs(f"{bold('Удаление float IP')} {esc(str(ex)[:300])}")
            await self.db.log_event("float_no_ipv4", name, {"floating_ip_id": fid})
            return

        if ipv4_in_pool(pub_ip, self._networks):
            await self.stats.add_pool_hit()
            await self.db.patch_account(name, {"brute_enabled": 0})
            await self.db.append_whitelist_float(name, fid)
            await self.db.log_event(
                "pool_hit_float",
                name,
                {"ip": pub_ip, "floating_ip_id": fid, "zone": zone_used},
            )
            msg = "\n".join(
                [
                    "🎯 " + bold("Попадание в ПНА"),
                    "📡 " + bold("IPv4-Address:") + f" {code(pub_ip)}",
                    "┈ " + bold("Аккаунт") + f" {code(name)}",
                    "┈ " + bold("Тип") + " плавающий публичный IP (Timeweb)",
                    "┈ " + bold("Зона") + f" {code(zone_used)}",
                    "┈ " + bold("Float id") + f" {code(fid)} — в белом списке, авто-удаление по таймеру отменяется",
                ]
            )
            await self.notify.totalresult(msg)
            asyncio.create_task(
                self._delete_float_later(row.api_key, fid, name),
                name=f"float-del-{fid[:8] if len(fid) >= 8 else fid}",
            )
        else:
            await self.stats.add_vm_deleted_no_pool()
            try:
                await self.twc.delete_floating_ip(row.api_key, fid)
            except TimewebApiError as ex:
                if not is_floating_ip_not_found(ex):
                    await self.notify.logs(f"{bold('Удаление float IP')} {esc(str(ex)[:300])}")
            except Exception as ex:
                await self.notify.logs(f"{bold('Удаление float IP')} {esc(str(ex)[:300])}")
            await self.db.log_event(
                "float_ip_not_in_pool",
                name,
                {"ip": pub_ip, "floating_ip_id": fid},
            )

    async def _delete_float_later(self, api_key: str, floating_ip_id: str, acc_name: str) -> None:
        delay = max(1, self.cfg.twc_vm_alivetime_minutes) * 60
        await asyncio.sleep(delay)
        row = await self.db.get_account(acc_name)
        if row and floating_ip_id in self.db.whitelist_float_ids(row):
            await self.notify.logs(
                "🔒 "
                + bold("Плавающий IP в белом списке")
                + f" {code(floating_ip_id)} — удаление по таймеру отменено."
            )
            return
        try:
            await self.twc.delete_floating_ip(api_key, floating_ip_id)
            await self.notify.logs(
                "\n".join(
                    [
                        "⏱ " + bold("Плавающий IP удалён по таймеру"),
                        f"Аккаунт: {code(acc_name)}",
                        f"id: {code(floating_ip_id)}",
                        "Чтобы не копились платные адреса.",
                    ]
                )
            )
            await self.db.log_event("float_ip_deleted_timer", acc_name, {"floating_ip_id": floating_ip_id})
        except TimewebApiError as ex:
            if is_floating_ip_not_found(ex):
                return
            await self.notify.logs(f"{bold('Удаление float IP')}: {esc(str(ex)[:400])}")
        except Exception as ex:
            await self.notify.logs(f"{bold('Удаление float IP')}: {esc(str(ex)[:400])}")

    async def _shutdown_later(self, api_key: str, server_id: int, vm_name: str, acc_name: str) -> None:
        delay = max(1, self.cfg.twc_vm_alivetime_minutes) * 60
        await asyncio.sleep(delay)
        try:
            await self.twc.shutdown_server(api_key, server_id)
            await self.notify.logs(
                "\n".join(
                    [
                        "⏱ " + bold("ВМ отключена по таймеру"),
                        "┈ " + bold("Аккаунт") + f" {code(acc_name)}",
                        "┈ " + bold("Сервер") + f" {code(vm_name)} · id {code(str(server_id))}",
                        "┈ снижение расхода баланса.",
                    ]
                )
            )
            await self.db.log_event("vm_shutdown_timer", acc_name, {"server_id": server_id})
        except TimewebApiError as ex:
            if is_server_not_found(ex):
                return
            await self.notify.logs(f"{bold('Ошибка выключения ВМ')}: {esc(str(ex)[:400])}")
        except Exception as ex:
            await self.notify.logs(f"{bold('Ошибка выключения ВМ')}: {esc(str(ex)[:400])}")

    async def _account_loop(self, name: str) -> None:
        while not self._stop.is_set():
            while self._brute_paused and not self._stop.is_set():
                await asyncio.sleep(1.0)
            try:
                await self.run_once_account(name)
            except asyncio.CancelledError:
                raise
            except Exception as ex:
                log.exception("account loop %s", name)
                await self.notify.logs(f"{bold('Worker')} {code(name)}: {esc(str(ex)[:500])}")
            await asyncio.sleep(3.0)

    async def _supervisor(self) -> None:
        sync_every = max(60, self.cfg.db_sync_time_minutes * 60)
        last_sync = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last_sync >= sync_every:
                last_sync = now
                for acc in await self.db.list_accounts():
                    try:
                        await sync_account(self.db, self.twc, self.cfg, acc.name)
                    except Exception:
                        log.exception("sync %s", acc.name)
            want = {a.name for a in await self.db.list_brute_accounts()}
            for n in want:
                if n not in self._tasks or self._tasks[n].done():
                    self._tasks[n] = asyncio.create_task(self._account_loop(n), name=f"brute-{n}")
            for n in list(self._tasks):
                if n not in want:
                    self._tasks[n].cancel()
                    del self._tasks[n]
            await asyncio.sleep(5.0)

    def start(self) -> None:
        if self._supervisor_task is None or self._supervisor_task.done():
            self._stop.clear()
            self._supervisor_task = asyncio.create_task(self._supervisor(), name="brute-supervisor")

    async def stop(self) -> None:
        self._stop.set()
        for t in self._tasks.values():
            t.cancel()
        self._tasks.clear()
        if self._supervisor_task:
            self._supervisor_task.cancel()
            try:
                await self._supervisor_task
            except asyncio.CancelledError:
                pass
            self._supervisor_task = None
