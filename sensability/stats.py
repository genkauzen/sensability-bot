from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class DailyStats:
    pool_hits: int = 0
    vm_created_ok: int = 0
    vm_created_fail: int = 0
    vm_deleted_no_pool: int = 0
    cooldown_24h_accounts: int = 0
    month_balance_errors: int = 0
    ipv4_checks: int = 0
    accounts_used: set[str] = field(default_factory=set)
    started_at: float = field(default_factory=time.time)

    def reset(self) -> None:
        self.pool_hits = 0
        self.vm_created_ok = 0
        self.vm_created_fail = 0
        self.vm_deleted_no_pool = 0
        self.cooldown_24h_accounts = 0
        self.month_balance_errors = 0
        self.ipv4_checks = 0
        self.accounts_used.clear()
        self.started_at = time.time()


class StatsCollector:
    def __init__(self) -> None:
        self._d = DailyStats()
        self._lock = asyncio.Lock()

    @property
    def snapshot(self) -> DailyStats:
        return self._d

    async def add_pool_hit(self) -> None:
        async with self._lock:
            self._d.pool_hits += 1

    async def add_vm_ok(self) -> None:
        async with self._lock:
            self._d.vm_created_ok += 1

    async def add_vm_fail(self) -> None:
        async with self._lock:
            self._d.vm_created_fail += 1

    async def add_vm_deleted_no_pool(self) -> None:
        async with self._lock:
            self._d.vm_deleted_no_pool += 1

    async def add_cooldown24(self) -> None:
        async with self._lock:
            self._d.cooldown_24h_accounts += 1

    async def add_month_err(self) -> None:
        async with self._lock:
            self._d.month_balance_errors += 1

    async def add_ipv4_check(self) -> None:
        async with self._lock:
            self._d.ipv4_checks += 1

    async def track_account(self, name: str) -> None:
        async with self._lock:
            self._d.accounts_used.add(name)

    async def reset_day(self) -> None:
        async with self._lock:
            self._d.reset()
