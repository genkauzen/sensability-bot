from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import aiosqlite

from sensability.config import Config


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    name TEXT PRIMARY KEY,
    api_key TEXT NOT NULL,
    acc_login TEXT,
    acc_email TEXT,
    brute_enabled INTEGER NOT NULL DEFAULT 1,
    limited_by_balance INTEGER NOT NULL DEFAULT 0,
    limited_by_month INTEGER NOT NULL DEFAULT 0,
    limited_by_month_ts REAL,
    limited_by_day INTEGER NOT NULL DEFAULT 0,
    limited_by_day_ts REAL,
    balance_cached REAL,
    currency TEXT,
    last_sync_ts REAL,
    acc_full_name TEXT,
    whitelist_servers TEXT,
    whitelist_floats TEXT,
    provider TEXT NOT NULL DEFAULT 'timeweb',
    slctl_rate_until REAL,
    whitelist_slctl TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    account TEXT,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


@dataclass
class AccountRow:
    name: str
    api_key: str
    acc_login: str | None
    acc_email: str | None
    brute_enabled: bool
    limited_by_balance: bool
    limited_by_month: bool
    limited_by_month_ts: float | None
    limited_by_day: bool
    limited_by_day_ts: float | None
    balance_cached: float | None
    currency: str | None
    last_sync_ts: float | None
    acc_full_name: str | None
    whitelist_servers: str | None
    whitelist_floats: str | None
    provider: str
    slctl_rate_until: float | None
    whitelist_slctl: str | None


def _row_to_account(r: aiosqlite.Row) -> AccountRow:
    return AccountRow(
        name=r["name"],
        api_key=r["api_key"],
        acc_login=r["acc_login"],
        acc_email=r["acc_email"],
        brute_enabled=bool(r["brute_enabled"]),
        limited_by_balance=bool(r["limited_by_balance"]),
        limited_by_month=bool(r["limited_by_month"]),
        limited_by_month_ts=r["limited_by_month_ts"],
        limited_by_day=bool(r["limited_by_day"]),
        limited_by_day_ts=r["limited_by_day_ts"],
        balance_cached=r["balance_cached"],
        currency=r["currency"],
        last_sync_ts=r["last_sync_ts"],
        acc_full_name=_col(r, "acc_full_name"),
        whitelist_servers=_col(r, "whitelist_servers"),
        whitelist_floats=_col(r, "whitelist_floats"),
        provider=str(_col(r, "provider") or "timeweb"),
        slctl_rate_until=_col(r, "slctl_rate_until"),
        whitelist_slctl=_col(r, "whitelist_slctl"),
    )


def _col(r: aiosqlite.Row, key: str) -> Any:
    try:
        return r[key]
    except (KeyError, IndexError):
        return None


class Database:
    def __init__(self, path: str) -> None:
        self._path = path

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(SCHEMA)
        await self._migrate_accounts_columns()
        await self._db.commit()

    async def _migrate_accounts_columns(self) -> None:
        cur = await self._db.execute("PRAGMA table_info(accounts)")
        rows = await cur.fetchall()
        have = {str(r[1]) for r in rows}
        for col, sql_typ in (
            ("acc_full_name", "TEXT"),
            ("whitelist_servers", "TEXT"),
            ("whitelist_floats", "TEXT"),
            ("provider", "TEXT"),
            ("slctl_rate_until", "REAL"),
            ("whitelist_slctl", "TEXT"),
        ):
            if col not in have:
                default = ""
                if col == "provider":
                    default = " DEFAULT 'timeweb'"
                await self._db.execute(f"ALTER TABLE accounts ADD COLUMN {col} {sql_typ}{default}")
        await self._db.execute(
            "UPDATE accounts SET provider='timeweb' WHERE provider IS NULL OR provider=''"
        )

    async def close(self) -> None:
        await self._db.close()

    async def add_account(self, name: str, api_key: str, provider: str = "timeweb") -> None:
        now = time.time()
        await self._db.execute(
            """
            INSERT INTO accounts (name, api_key, brute_enabled, last_sync_ts, provider)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                api_key=excluded.api_key,
                brute_enabled=1,
                last_sync_ts=excluded.last_sync_ts,
                provider=excluded.provider
            """,
            (name, api_key, now, provider),
        )
        await self._db.commit()

    async def delete_account(self, name: str) -> bool:
        cur = await self._db.execute("DELETE FROM accounts WHERE name=?", (name,))
        await self._db.commit()
        return cur.rowcount > 0

    async def set_brute_enabled(self, name: str, enabled: bool) -> bool:
        cur = await self._db.execute(
            "UPDATE accounts SET brute_enabled=? WHERE name=?",
            (1 if enabled else 0, name),
        )
        await self._db.commit()
        return cur.rowcount > 0

    async def get_account(self, name: str) -> AccountRow | None:
        cur = await self._db.execute("SELECT * FROM accounts WHERE name=?", (name,))
        r = await cur.fetchone()
        return _row_to_account(r) if r else None

    async def list_accounts(self) -> list[AccountRow]:
        cur = await self._db.execute("SELECT * FROM accounts ORDER BY name")
        rows = await cur.fetchall()
        return [_row_to_account(r) for r in rows]

    async def list_brute_accounts(self) -> list[AccountRow]:
        cur = await self._db.execute(
            "SELECT * FROM accounts WHERE brute_enabled=1 ORDER BY name"
        )
        rows = await cur.fetchall()
        return [_row_to_account(r) for r in rows]

    async def patch_account(self, name: str, fields: dict[str, Any]) -> None:
        allowed = frozenset(
            {
                "acc_login",
                "acc_email",
                "balance_cached",
                "currency",
                "limited_by_balance",
                "limited_by_month",
                "limited_by_month_ts",
                "limited_by_day",
                "limited_by_day_ts",
                "brute_enabled",
                "acc_full_name",
                "whitelist_servers",
                "whitelist_floats",
                "slctl_rate_until",
                "whitelist_slctl",
            }
        )
        fields = {k: v for k, v in fields.items() if k in allowed}
        if not fields:
            return
        cols: list[str] = []
        vals: list[Any] = []
        for key, val in fields.items():
            cols.append(f"{key}=?")
            vals.append(val)
        cols.append("last_sync_ts=?")
        vals.append(time.time())
        vals.append(name)
        q = f"UPDATE accounts SET {', '.join(cols)} WHERE name=?"
        await self._db.execute(q, vals)
        await self._db.commit()

    async def heal_account(self, name: str) -> bool:
        cur = await self._db.execute(
            """
            UPDATE accounts SET
                limited_by_balance=0,
                limited_by_month=0,
                limited_by_month_ts=NULL,
                limited_by_day=0,
                limited_by_day_ts=NULL,
                slctl_rate_until=NULL
            WHERE name=?
            """,
            (name,),
        )
        await self._db.commit()
        return cur.rowcount > 0

    async def append_whitelist_server(self, name: str, server_id: int) -> None:
        row = await self.get_account(name)
        if not row:
            return
        cur: list[Any]
        try:
            cur = json.loads(row.whitelist_servers or "[]")
        except json.JSONDecodeError:
            cur = []
        if not isinstance(cur, list):
            cur = []
        if server_id not in cur:
            cur.append(server_id)
        await self.patch_account(name, {"whitelist_servers": json.dumps(cur)})

    async def append_whitelist_float(self, name: str, floating_ip_id: str) -> None:
        row = await self.get_account(name)
        if not row:
            return
        try:
            cur = json.loads(row.whitelist_floats or "[]")
        except json.JSONDecodeError:
            cur = []
        if not isinstance(cur, list):
            cur = []
        if floating_ip_id not in cur:
            cur.append(floating_ip_id)
        await self.patch_account(name, {"whitelist_floats": json.dumps(cur)})

    async def append_whitelist_slctl(self, name: str, server_id: str) -> None:
        row = await self.get_account(name)
        if not row:
            return
        try:
            cur = json.loads(row.whitelist_slctl or "[]")
        except json.JSONDecodeError:
            cur = []
        if not isinstance(cur, list):
            cur = []
        sid = str(server_id).strip()
        if sid and sid not in cur:
            cur.append(sid)
        await self.patch_account(name, {"whitelist_slctl": json.dumps(cur)})

    def whitelist_slctl_ids(self, row: AccountRow) -> list[str]:
        try:
            raw = json.loads(row.whitelist_slctl or "[]")
        except json.JSONDecodeError:
            return []
        if not isinstance(raw, list):
            return []
        return [str(x).strip() for x in raw if x is not None and str(x).strip()]

    def whitelist_server_ids(self, row: AccountRow) -> list[int]:
        try:
            raw = json.loads(row.whitelist_servers or "[]")
        except json.JSONDecodeError:
            return []
        if not isinstance(raw, list):
            return []
        out: list[int] = []
        for x in raw:
            try:
                out.append(int(x))
            except (TypeError, ValueError):
                continue
        return out

    def whitelist_float_ids(self, row: AccountRow) -> list[str]:
        try:
            raw = json.loads(row.whitelist_floats or "[]")
        except json.JSONDecodeError:
            return []
        if not isinstance(raw, list):
            return []
        return [str(x) for x in raw if x is not None]

    async def log_event(self, kind: str, account: str | None, detail: Any) -> None:
        payload = json.dumps(detail, ensure_ascii=False) if not isinstance(detail, str) else detail
        await self._db.execute(
            "INSERT INTO events (ts, kind, account, detail) VALUES (?,?,?,?)",
            (time.time(), kind, account, payload),
        )
        await self._db.commit()

    async def events_since(self, ts: float) -> list[tuple[float, str, str | None, str]]:
        cur = await self._db.execute(
            "SELECT ts, kind, account, detail FROM events WHERE ts >= ? ORDER BY id",
            (ts,),
        )
        rows = await cur.fetchall()
        return [(r[0], r[1], r[2], r[3]) for r in rows]


def db_path(cfg: Config) -> str:
    return str(cfg.data_dir / "sensability.db")
