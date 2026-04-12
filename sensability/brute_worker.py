from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any

from sensability.account_sync import (
    account_eligible_for_brute,
    account_prefers_floating_ip_probe,
    sync_account,
)
from sensability.config import Config
from sensability.db import AccountRow, Database
from sensability.ip_pool import ipv4_in_any_potential, ipv4_in_pool
from sensability.notify import TelegramNotify
from sensability.regru_client import (
    RegruApiError,
    RegruClient,
    regru_ip_record_is_spb_ipv4,
    regru_is_spb_region,
)
from sensability.regru_constants import REGRU_REGION_SPB
from sensability.regru_ops import regru_pick_spb_plan_and_image, regru_refresh_whitelist
from sensability.stats import StatsCollector
from sensability.tg_format import bold, code, esc, spoiler_code
from sensability.twc_constants import (
    TWC_BANDWIDTH,
    TWC_OS_ID,
    TWC_PRESET_ID,
)
from sensability.slctl_constants import SLCTL_RATE_COOLDOWN_SEC
from sensability.slctl_client import (
    SelectelClient,
    SlctlApiError,
    is_slctl_rate_limit_error,
    parse_error_message as slctl_parse_error_message,
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
    timeweb_server_zone_label,
)

if TYPE_CHECKING:
    from sensability.twc_client import TimewebClient

log = logging.getLogger("sensability.brute")

POLL_INTERVAL = 3.0
POLL_ATTEMPTS = 45
NOTFOUND_GIVEUP = 1

LIVE_SVC_TIMEWEB = "Timeweb Cloud"
LIVE_SVC_REGRU = "Reg.ru CloudVPS"
LIVE_SVC_SELECTEL = "Selectel Cloud"


def _live_line_service(label: str) -> str:
    return "┈ " + bold("Сервис") + f" {code(label)}"


class BruteOrchestrator:
    def __init__(
        self,
        cfg: Config,
        db: Database,
        twc: TimewebClient,
        slctl: SelectelClient,
        regru: RegruClient,
        stats: StatsCollector,
        notify: TelegramNotify,
        networks: tuple,
        potential_networks: tuple,
        networks_selectel: tuple,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.twc = twc
        self.slctl = slctl
        self._regru = regru
        self.stats = stats
        self.notify = notify
        self._networks = networks
        self._potential_networks = potential_networks
        self._networks_selectel = networks_selectel
        self._sem_twc = asyncio.Semaphore(cfg.twc_atmoment_acc)
        self._sem_slctl = asyncio.Semaphore(cfg.slctl_atmoment_acc)
        self._sem_regru = asyncio.Semaphore(cfg.regru_atmoment_acc)
        self._slctl_float_rr = 0
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

    def _ip_live_extra_lines(
        self,
        pub_ip: str | None,
        *,
        pool_networks: tuple | None = None,
    ) -> list[str]:
        nets = pool_networks if pool_networks is not None else self._networks
        if not pub_ip:
            return [
                "┈ " + bold("Пул ПНА") + ": —",
                "┈ " + bold("Потенциал (±2 к октетам)") + ": —",
            ]
        in_pool = ipv4_in_pool(pub_ip, nets)
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
        row0 = await sync_account(self.db, self.twc, self.slctl, self._regru, self.cfg, name)
        if not row0:
            return
        if row0.provider == "selectel":
            sem = self._sem_slctl
        elif row0.provider == "regru":
            sem = self._sem_regru
        else:
            sem = self._sem_twc
        async with sem:
            if self._brute_paused:
                return
            row = await sync_account(self.db, self.twc, self.slctl, self._regru, self.cfg, name)
            if not row:
                return
            if not account_eligible_for_brute(row, self.cfg):
                return

            if row.provider == "selectel":
                await self._run_brute_selectel(name, row)
            elif row.provider == "regru":
                await self._run_brute_regru(name, row)
            elif account_prefers_floating_ip_probe(row):
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
        last_srv_snap: dict[str, Any] | None = None

        def _twc_vm_region_live() -> str:
            src = last_srv_snap if last_srv_snap is not None else server
            z = timeweb_server_zone_label(src)
            if z != "—":
                return z
            cfgz = (self.cfg.twc_vm_region or "").strip()
            return cfgz if cfgz else "—"

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
                        last_srv_snap = s
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
                                    _live_line_service(LIVE_SVC_TIMEWEB),
                                    "┈ " + bold("Аккаунт") + f" {code(name)}",
                                    "┈ " + bold("ВМ") + f" {code(vm_name)}",
                                    "┈ " + bold("Регион") + f" {code(_twc_vm_region_live())}",
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
            _live_line_service(LIVE_SVC_TIMEWEB),
            "┈ " + bold("Аккаунт") + f" {code(name)}",
            "┈ " + bold("ВМ") + f" {code(vm_name)}",
            "┈ " + bold("Регион") + f" {code(_twc_vm_region_live())}",
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

        zones = await self.db.get_twc_float_ip_zones_for_brute()
        data: dict | None = None
        zone_used = ""
        for zone in zones:
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
                if looks_like_daily_limit_error(msg) or e.status == 429:
                    await self.db.patch_account(
                        name,
                        {"limited_by_month": 1, "limited_by_month_ts": time.time()},
                    )
                    await self.stats.add_month_err()
                    await self.db.log_event(
                        "month_limit_float_create",
                        name,
                        {"zone": zone, "message": msg[:2000]},
                    )
                    return
                continue

        if not data:
            await self.stats.add_vm_fail()
            await self.db.log_event("float_ip_create_fail", name, {"zones": list(zones)})
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
                # После успешного POST float IP ответ «Daily limit» у API по смыслу ближе к месячному лимиту/тарифу, не к суточному перебору ВМ.
                if looks_like_daily_limit_error(pmsg) or ex.status == 429:
                    await self.db.patch_account(
                        name,
                        {"limited_by_month": 1, "limited_by_month_ts": time.time()},
                    )
                    await self.stats.add_month_err()
                    await self.db.log_event("month_limit_float_poll", name, {"msg": pmsg[:800]})
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
                                    _live_line_service(LIVE_SVC_TIMEWEB),
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
            _live_line_service(LIVE_SVC_TIMEWEB),
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

    def _next_slctl_float_region(self) -> str:
        regions = self.cfg.slctl_float_regions
        if not regions:
            regions = ("ru-7",)
        reg = regions[self._slctl_float_rr % len(regions)]
        self._slctl_float_rr += 1
        return reg

    async def _run_brute_regru(self, name: str, row: AccountRow) -> None:
        await self.stats.track_account(name, row.balance_cached)
        await regru_refresh_whitelist(self.db, self._regru, self.cfg, name, row, delete_bot_vms=True)
        row2 = await self.db.get_account(name)
        if not row2:
            return
        if row2.regru_extra_ip_ok != 0:
            anchor = await self._regru_spb_anchor_reglet_id(row2)
            if anchor is not None:
                if await self._regru_brute_extra_ip_once(name, row2, anchor):
                    return
        await self._regru_brute_vm_once(name, row2)

    async def _regru_spb_anchor_reglet_id(self, row: AccountRow) -> int | None:
        try:
            reglets = await self._regru.list_reglets(row.api_key)
        except Exception:
            return None
        for raw in reglets:
            if not isinstance(raw, dict) or not regru_is_spb_region(raw):
                continue
            st = str(raw.get("status") or "").lower()
            if st in ("destroyed", "deleted", "archived", "removed"):
                continue
            try:
                return int(raw.get("id"))
            except (TypeError, ValueError):
                continue
        return None

    async def _regru_brute_extra_ip_once(
        self, name: str, row: AccountRow, anchor_id: int
    ) -> bool:
        """True — цикл «доп. IP» отработан (в т.ч. 403 → только ВМ дальше), не вызывать ВМ в этом же проходе."""
        tok = row.api_key
        before: set[int] = set()
        try:
            for rec in await self._regru.list_ips(tok, reglet_id=anchor_id):
                if isinstance(rec, dict) and rec.get("id") is not None:
                    try:
                        before.add(int(rec["id"]))
                    except (TypeError, ValueError):
                        pass
        except RegruApiError as e:
            if e.status in (401, 403):
                await self.db.patch_account(name, {"regru_extra_ip_ok": 0})
                return True
            if self.cfg.full_logs:
                await self.notify.logs(f"{bold('Reg.ru list_ips')} {esc(name)}: {esc(str(e)[:300])}")
            return True
        except Exception:
            return True

        try:
            await self._regru.order_extra_ips(tok, anchor_id, ipv4_count=1)
        except RegruApiError as e:
            if e.status in (401, 403, 402):
                await self.db.patch_account(name, {"regru_extra_ip_ok": 0})
                return True
            if self.cfg.full_logs:
                await self.notify.logs(
                    f"{bold('Reg.ru заказ IP')} {esc(name)}: {esc(str(e)[:400])}"
                )
            return True
        except Exception:
            return True

        await self.db.patch_account(name, {"regru_extra_ip_ok": 1})

        new_id: int | None = None
        new_ip: str | None = None
        for attempt in range(POLL_ATTEMPTS):
            if self._stop.is_set() or self._brute_paused:
                break
            if attempt:
                await asyncio.sleep(POLL_INTERVAL)
            await self.stats.add_ipv4_check()
            try:
                for rec in await self._regru.list_ips(tok, reglet_id=anchor_id):
                    if not isinstance(rec, dict):
                        continue
                    try:
                        iid = int(rec["id"])
                    except (TypeError, ValueError):
                        continue
                    if iid in before:
                        continue
                    if str(rec.get("type") or "").lower() != "ipv4":
                        continue
                    ip_s = str(rec.get("ip") or "").strip()
                    if ip_s and ip_s.count(".") == 3:
                        new_id, new_ip = iid, ip_s
                        break
                if new_ip:
                    break
            except RegruApiError as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Reg.ru poll ips')} {esc(str(ex)[:200])}")
            except Exception:
                pass

        live_r = [
            "📡 " + bold("Live — Reg.ru доп. IPv4 (СПб)"),
            _live_line_service(LIVE_SVC_REGRU),
            "┈ " + bold("Аккаунт") + f" {code(name)}",
            "┈ " + bold("Реглет") + f" {code(str(anchor_id))}",
            "┈ " + bold("IPv4") + f" {code(new_ip or '—')}",
        ]
        live_r.extend(self._ip_live_extra_lines(new_ip))
        await self.notify.live("\n".join(live_r))

        if not new_ip or new_id is None:
            return True

        if ipv4_in_pool(new_ip, self._networks):
            await self.stats.add_pool_hit()
            await self.db.patch_account(name, {"brute_enabled": 0})
            await self.db.append_whitelist_regru_ip(name, new_id)
            await self.db.log_event(
                "pool_hit_regru_ip", name, {"ip": new_ip, "ip_row_id": new_id}
            )
            msg = "\n".join(
                [
                    "🎯 " + bold("Попадание в ПНА"),
                    "📡 " + bold("Reg.ru") + " доп. IPv4 (СПб)",
                    "┈ " + bold("Аккаунт") + f" {code(name)}",
                    "┈ " + bold("IPv4") + f" {code(new_ip)}",
                    "┈ " + bold("Запись IP id") + f" {code(str(new_id))} — в белом списке",
                ]
            )
            await self.notify.totalresult(msg)
            asyncio.create_task(
                self._delete_regru_ip_later(tok, new_id, new_ip, name),
                name=f"regru-ip-{new_id}",
            )
        else:
            await self.stats.add_vm_deleted_no_pool()
            try:
                await self._regru.delete_ip(tok, str(new_id))
            except RegruApiError as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Reg.ru delete_ip')} {esc(str(ex)[:300])}")
            except Exception:
                pass
            await self.db.log_event(
                "regru_ip_not_in_pool", name, {"ip": new_ip, "ip_row_id": new_id}
            )
        return True

    async def _regru_brute_vm_once(self, name: str, row: AccountRow) -> None:
        picked = await regru_pick_spb_plan_and_image(self._regru, row.api_key)
        if not picked:
            await self.stats.add_vm_fail()
            await self.db.log_event(
                "regru_no_plan_image", name, {"region": REGRU_REGION_SPB}
            )
            return
        size_slug, image_slug = picked
        vm_name = f"{self.cfg.twc_vm_name}-regru-{row.name}-{uuid.uuid4().hex[:8]}"
        if self.cfg.full_logs:
            await self.notify.logs(
                f"{bold('Reg.ru')} <code>POST /v1/reglets</code> {code(REGRU_REGION_SPB)} · {esc(name)}"
            )
        try:
            reglet = await self._regru.create_reglet(
                row.api_key,
                name=vm_name,
                size_slug=size_slug,
                image_slug=image_slug,
            )
        except RegruApiError as e:
            if self.cfg.full_logs:
                await self.notify.logs(
                    f"{bold('Reg.ru ошибка')} {e.status}: {esc(e.body[:800])}"
                )
            await self.stats.add_vm_fail()
            await self.db.log_event(
                "regru_create_fail", name, {"status": e.status, "msg": e.body[:2000]}
            )
            return

        await self.stats.add_vm_ok()
        try:
            rid = int(reglet.get("id") or 0)
        except (TypeError, ValueError):
            rid = 0
        if not rid:
            await self.stats.add_vm_fail()
            return

        pub_ip: str | None = None
        for attempt in range(POLL_ATTEMPTS):
            if self._stop.is_set() or self._brute_paused:
                break
            if attempt:
                await asyncio.sleep(POLL_INTERVAL)
            await self.stats.add_ipv4_check()
            try:
                r = await self._regru.get_reglet(row.api_key, rid)
                ip = str(r.get("ip") or "").strip()
                if ip and ip.count(".") == 3:
                    pub_ip = ip
                    break
            except RegruApiError as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Reg.ru poll reglet')} {esc(str(ex)[:200])}")
            except Exception as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Reg.ru poll')} {esc(str(ex)[:200])}")

        live_v = [
            "🖥 " + bold("Live — Reg.ru CloudVPS (СПб)"),
            _live_line_service(LIVE_SVC_REGRU),
            "┈ " + bold("Аккаунт") + f" {code(name)}",
            "┈ " + bold("Регион") + f" {code(REGRU_REGION_SPB)}",
            "┈ " + bold("IPv4") + f" {code(pub_ip or '—')}",
        ]
        live_v.extend(self._ip_live_extra_lines(pub_ip))
        await self.notify.live("\n".join(live_v))

        if not pub_ip:
            try:
                await self._regru.delete_reglet(row.api_key, rid)
            except Exception:
                pass
            await self.db.log_event("regru_no_ipv4", name, {"reglet_id": rid})
            return

        if ipv4_in_pool(pub_ip, self._networks):
            await self.stats.add_pool_hit()
            await self.db.patch_account(name, {"brute_enabled": 0})
            await self.db.append_whitelist_regru(name, rid)
            await self.db.log_event("pool_hit_regru", name, {"ip": pub_ip, "reglet_id": rid})
            msg = "\n".join(
                [
                    "🎯 " + bold("Попадание в ПНА"),
                    "🖥 " + bold("Reg.ru") + f" {code(REGRU_REGION_SPB)}",
                    "┈ " + bold("Аккаунт") + f" {code(name)}",
                    "┈ " + bold("IPv4") + f" {code(pub_ip)}",
                    "┈ " + bold("Reglet id") + f" {code(str(rid))} — в белом списке",
                ]
            )
            await self.notify.totalresult(msg)
            asyncio.create_task(
                self._delete_regru_reglet_later(row.api_key, rid, name),
                name=f"regru-vm-{rid}",
            )
        else:
            await self.stats.add_vm_deleted_no_pool()
            try:
                await self._regru.delete_reglet(row.api_key, rid)
            except RegruApiError as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Reg.ru delete reglet')} {esc(str(ex)[:300])}")
            except Exception:
                pass
            await self.db.log_event("regru_ip_not_in_pool", name, {"ip": pub_ip, "reglet_id": rid})

    async def _run_brute_selectel(self, name: str, row: AccountRow) -> None:
        await self.stats.track_account(name, row.balance_cached)
        reg = self._next_slctl_float_region()
        if self.cfg.full_logs:
            await self.notify.logs(
                f"{bold('Selectel')} <code>Neutron POST /floatingips</code> · {esc(name)} · {code(reg)}"
            )
        try:
            fi = await self.slctl.create_floating_ip(
                row.api_key,
                reg,
                description=f"sensability-{name}"[:240],
            )
        except SlctlApiError as e:
            msg = slctl_parse_error_message(e)
            if self.cfg.full_logs:
                await self.notify.logs(f"{bold('Selectel ошибка')} {e.status}: {esc(msg[:800])}")
            if is_slctl_rate_limit_error(e.status):
                await self.db.patch_account(
                    name,
                    {"slctl_rate_until": time.time() + SLCTL_RATE_COOLDOWN_SEC},
                )
                await self.db.log_event("slctl_rate_limit", name, {"status": e.status, "msg": msg[:2000]})
                return
            await self.stats.add_vm_fail()
            await self.db.log_event(
                "slctl_fip_create_fail", name, {"status": e.status, "msg": msg[:2000], "region": reg}
            )
            return

        await self.stats.add_vm_ok()
        fid = str(fi.get("id") or "").strip()
        if not fid:
            await self.stats.add_vm_fail()
            return

        pub_ip = str(fi.get("floating_ip_address") or "").strip()
        if pub_ip and pub_ip.count(".") != 3:
            pub_ip = None

        notfound_streak = 0
        for _ in range(POLL_ATTEMPTS):
            if self._stop.is_set() or self._brute_paused:
                break
            if pub_ip:
                break
            await asyncio.sleep(POLL_INTERVAL)
            await self.stats.add_ipv4_check()
            try:
                fi2 = await self.slctl.get_floating_ip(row.api_key, reg, fid)
                ip = str(fi2.get("floating_ip_address") or "").strip()
                if ip and ip.count(".") == 3:
                    pub_ip = ip
                    break
            except SlctlApiError as ex:
                msg = slctl_parse_error_message(ex)
                if is_slctl_rate_limit_error(ex.status):
                    await self.db.patch_account(
                        name,
                        {"slctl_rate_until": time.time() + SLCTL_RATE_COOLDOWN_SEC},
                    )
                    await self.db.log_event("slctl_rate_limit_poll", name, {"msg": msg[:800]})
                    try:
                        await self.slctl.delete_floating_ip(row.api_key, reg, fid)
                    except Exception:
                        pass
                    return
                if ex.status == 404:
                    notfound_streak += 1
                    if notfound_streak >= NOTFOUND_GIVEUP:
                        await self.db.log_event("slctl_fip_gone", name, {"fip_id": fid})
                        return
                elif self.cfg.full_logs:
                    await self.notify.logs(f"{bold('poll fip')} {esc(name)}: {esc(str(ex)[:200])}")
            except Exception as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('poll fip')} {esc(name)}: {esc(str(ex)[:200])}")

        live_s = [
            "📡 " + bold("Live — Selectel плавающий IPv4"),
            _live_line_service(LIVE_SVC_SELECTEL),
            "┈ " + bold("Аккаунт") + f" {code(name)}",
            "┈ " + bold("Регион") + f" {code(reg)}",
            "┈ " + bold("IPv4") + f" {code(pub_ip or '—')}",
        ]
        live_s.extend(self._ip_live_extra_lines(pub_ip, pool_networks=self._networks_selectel))
        await self.notify.live("\n".join(live_s))

        if not pub_ip:
            if notfound_streak >= NOTFOUND_GIVEUP:
                return
            try:
                await self.slctl.delete_floating_ip(row.api_key, reg, fid)
            except SlctlApiError as ex:
                if ex.status != 404 and self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Удаление FIP')}: {esc(str(ex)[:300])}")
            except Exception as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Удаление FIP')}: {esc(str(ex)[:300])}")
            await self.db.log_event("slctl_fip_no_addr", name, {"fip_id": fid, "region": reg})
            return

        if ipv4_in_pool(pub_ip, self._networks_selectel):
            await self.stats.add_pool_hit()
            await self.db.patch_account(name, {"brute_enabled": 0})
            await self.db.append_whitelist_slctl_fip(name, fid)
            await self.db.log_event(
                "pool_hit_slctl_fip", name, {"ip": pub_ip, "fip_id": fid, "region": reg}
            )
            msg = "\n".join(
                [
                    "🎯 " + bold("Попадание в ПНА"),
                    "📡 " + bold("Selectel Neutron") + " плавающий IPv4",
                    "┈ " + bold("Аккаунт") + f" {code(name)}",
                    "┈ " + bold("Публичный IPv4") + f" {code(pub_ip)}",
                    "┈ " + bold("FIP id") + f" {code(fid)} · регион {code(reg)}",
                ]
            )
            await self.notify.totalresult(msg)
            asyncio.create_task(
                self._delete_slctl_fip_later(row.api_key, reg, fid, name),
                name=f"slctl-fip-{fid[:8]}",
            )
        else:
            await self.stats.add_vm_deleted_no_pool()
            try:
                await self.slctl.delete_floating_ip(row.api_key, reg, fid)
            except SlctlApiError as ex:
                if ex.status != 404 and self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Удаление FIP')}: {esc(str(ex)[:300])}")
            except Exception as ex:
                if self.cfg.full_logs:
                    await self.notify.logs(f"{bold('Удаление FIP')}: {esc(str(ex)[:300])}")
            await self.db.log_event(
                "slctl_fip_not_in_pool", name, {"ip": pub_ip, "fip_id": fid, "region": reg}
            )

    async def _delete_slctl_fip_later(
        self, api_key: str, region: str, fip_id: str, acc_name: str
    ) -> None:
        delay = max(1, self.cfg.twc_vm_alivetime_minutes) * 60
        await asyncio.sleep(delay)
        row = await self.db.get_account(acc_name)
        if row and fip_id in self.db.whitelist_slctl_fip_ids(row):
            await self.notify.logs(
                "🔒 "
                + bold("Selectel FIP в белом списке")
                + f" {code(fip_id)} — удаление по таймеру отменено."
            )
            return
        try:
            await self.slctl.delete_floating_ip(api_key, region, fip_id)
            await self.notify.logs(
                "\n".join(
                    [
                        "⏱ " + bold("Selectel FIP удалён по таймеру"),
                        f"Аккаунт: {code(acc_name)}",
                        f"id: {code(fip_id)} · {code(region)}",
                    ]
                )
            )
            await self.db.log_event("slctl_fip_deleted_timer", acc_name, {"fip_id": fip_id})
        except SlctlApiError as ex:
            if ex.status == 404:
                return
            await self.notify.logs(f"{bold('Удаление FIP')}: {esc(str(ex)[:400])}")
        except Exception as ex:
            await self.notify.logs(f"{bold('Удаление FIP')}: {esc(str(ex)[:400])}")

    async def _delete_regru_ip_later(
        self, token: str, ip_row_id: int, ip_str: str, acc_name: str
    ) -> None:
        delay = max(1, self.cfg.twc_vm_alivetime_minutes) * 60
        await asyncio.sleep(delay)
        row = await self.db.get_account(acc_name)
        if row and ip_row_id in self.db.whitelist_regru_ip_ids(row):
            await self.notify.logs(
                "🔒 "
                + bold("Reg.ru IP в белом списке")
                + f" {code(str(ip_row_id))} — удаление по таймеру отменено."
            )
            return
        for ident in (str(ip_row_id), ip_str):
            try:
                await self._regru.delete_ip(token, ident)
                await self.db.log_event(
                    "regru_ip_deleted_timer", acc_name, {"ip_row_id": ip_row_id}
                )
                return
            except RegruApiError:
                continue
            except Exception:
                continue

    async def _delete_regru_reglet_later(self, token: str, reglet_id: int, acc_name: str) -> None:
        delay = max(1, self.cfg.twc_vm_alivetime_minutes) * 60
        await asyncio.sleep(delay)
        row = await self.db.get_account(acc_name)
        if row and reglet_id in self.db.whitelist_regru_ids(row):
            await self.notify.logs(
                "🔒 "
                + bold("Reg.ru reglet в белом списке")
                + f" {code(str(reglet_id))} — удаление по таймеру отменено."
            )
            return
        try:
            await self._regru.delete_reglet(token, reglet_id)
            await self.db.log_event("regru_deleted_timer", acc_name, {"reglet_id": reglet_id})
        except Exception:
            pass

    async def _delete_slctl_later(self, api_key: str, region: str, server_id: str, acc_name: str) -> None:
        delay = max(1, self.cfg.twc_vm_alivetime_minutes) * 60
        await asyncio.sleep(delay)
        row = await self.db.get_account(acc_name)
        if row and server_id in self.db.whitelist_slctl_ids(row):
            await self.notify.logs(
                "🔒 "
                + bold("Selectel ВМ в белом списке")
                + f" {code(server_id)} — удаление по таймеру отменено."
            )
            return
        try:
            await self.slctl.delete_server(api_key, region, server_id)
            await self.notify.logs(
                "\n".join(
                    [
                        "⏱ " + bold("Selectel ВМ удалена по таймеру"),
                        f"Аккаунт: {code(acc_name)}",
                        f"id: {code(server_id)}",
                    ]
                )
            )
            await self.db.log_event("slctl_deleted_timer", acc_name, {"server_id": server_id})
        except SlctlApiError as ex:
            if ex.status == 404:
                return
            await self.notify.logs(f"{bold('Удаление Nova')}: {esc(str(ex)[:400])}")
        except Exception as ex:
            await self.notify.logs(f"{bold('Удаление Nova')}: {esc(str(ex)[:400])}")

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

    async def _supervisor(self) -> None:
        sync_every = max(60, self.cfg.db_sync_time_minutes * 60)
        last_sync = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last_sync >= sync_every:
                last_sync = now
                for acc in await self.db.list_accounts():
                    try:
                        await sync_account(
                            self.db, self.twc, self.slctl, self._regru, self.cfg, acc.name
                        )
                    except Exception:
                        log.exception("sync %s", acc.name)
            while self._brute_paused and not self._stop.is_set():
                await asyncio.sleep(1.0)
            accs = await self.db.list_brute_accounts()
            if accs and not self._stop.is_set():
                await asyncio.gather(
                    *[self.run_once_account(a.name) for a in accs],
                    return_exceptions=True,
                )
            await asyncio.sleep(3.0)

    def start(self) -> None:
        if self._supervisor_task is None or self._supervisor_task.done():
            self._stop.clear()
            self._supervisor_task = asyncio.create_task(self._supervisor(), name="brute-supervisor")

    async def stop(self) -> None:
        self._stop.set()
        if self._supervisor_task:
            self._supervisor_task.cancel()
            try:
                await self._supervisor_task
            except asyncio.CancelledError:
                pass
            self._supervisor_task = None
