from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _int(v: str | None, default: int) -> int:
    if v is None or str(v).strip() == "":
        return default
    return int(str(v).strip())


def _opt_int(v: str | None) -> int | None:
    if v is None or str(v).strip() == "":
        return None
    return int(str(v).strip())


def _float(v: str | None, default: float) -> float:
    if v is None or str(v).strip() == "":
        return default
    return float(str(v).strip())


def _csv_ids(v: str | None) -> frozenset[str]:
    if not v or not str(v).strip():
        return frozenset()
    return frozenset(x.strip() for x in str(v).split(",") if x.strip())


@dataclass(frozen=True)
class Config:
    bot_token: str
    tg_proxy_use: bool
    tg_proxy_url: str | None
    group_id: int
    topic_logs: int | None
    topic_updaywork: int | None
    topic_live: int | None
    topic_terminal: int | None
    topic_accountverify: int | None
    topic_totalresult: int | None
    full_logs: bool
    updaywork_upload_time: str
    terminal_public_access: bool
    terminal_user_ids: frozenset[str]
    accountverify_public_access: bool
    accountverify_user_ids: frozenset[str]
    twc_proxy_use: bool
    twc_proxy_url: str | None
    twc_vm_name: str
    twc_vm_region: str
    twc_preset_id: int
    twc_os_id: int
    twc_bandwidth: int
    twc_atmoment_acc: int
    twc_minimum_rubles: float
    twc_vm_alivetime_minutes: int
    db_sync_time_minutes: int
    data_dir: Path
    compose_dir: Path
    subnets_path: Path


def load_config() -> Config:
    load_dotenv()
    data_dir = Path(os.getenv("SENSABILITY_DATA_DIR", "/app/data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parent.parent
    subnets = Path(os.getenv("SENSABILITY_SUBNETS_PATH", str(root / "subnets.txt")))
    compose = Path(os.getenv("SENSABILITY_COMPOSE_DIR", "/compose"))

    return Config(
        bot_token=os.getenv("BOT_TOKEN", "").strip(),
        tg_proxy_use=_bool(os.getenv("TG_PROXY_USE"), False),
        tg_proxy_url=(os.getenv("TG_PROXY_URL") or "").strip() or None,
        group_id=_int(os.getenv("GROUP_ID"), 0),
        topic_logs=_opt_int(os.getenv("TOPIC_ID_LOGS")),
        topic_updaywork=_opt_int(os.getenv("TOPIC_ID_UPDAYWORK")),
        topic_live=_opt_int(os.getenv("TOPIC_ID_LIVE")),
        topic_terminal=_opt_int(os.getenv("TOPIC_ID_TERMINAL")),
        topic_accountverify=_opt_int(os.getenv("TOPIC_ID_ACCOUNTVERIFY")),
        topic_totalresult=_opt_int(os.getenv("TOPIC_ID_TOTALRESULT")),
        full_logs=_bool(os.getenv("FULL_LOGS"), False),
        updaywork_upload_time=(os.getenv("UPDAYWORK_UPLOADTIME") or "00:00").strip(),
        terminal_public_access=_bool(os.getenv("TERMINAL_PUBLIC_ACCESS"), False),
        terminal_user_ids=_csv_ids(os.getenv("TERMINAL_USERID_ACCESS")),
        accountverify_public_access=_bool(os.getenv("ACCOUNTVERIFY_PUBLIC_ACCESS"), False),
        accountverify_user_ids=_csv_ids(os.getenv("ACCOUNTVERIFY_USERID_ACCESS")),
        twc_proxy_use=_bool(os.getenv("TWC_PROXY_USE"), False),
        twc_proxy_url=(os.getenv("TWC_PROXY_URL") or "").strip() or None,
        twc_vm_name=(os.getenv("TWC_VM_NAME") or "sensability-vm").strip(),
        twc_vm_region=(os.getenv("TWC_VM_REGION") or "spb-3").strip(),
        twc_preset_id=_int(os.getenv("TWC_PRESET_ID"), 122),
        twc_os_id=_int(os.getenv("TWC_OS_ID"), 65),
        twc_bandwidth=_int(os.getenv("TWC_BANDWIDTH"), 200),
        twc_atmoment_acc=max(1, _int(os.getenv("TWC_ATMOMENT_ACC"), 3)),
        twc_minimum_rubles=_float(os.getenv("TWC_MINIMUM_RUBLES"), 0.0),
        twc_vm_alivetime_minutes=max(1, _int(os.getenv("TWC_VM_ALIVETIME"), 5)),
        db_sync_time_minutes=max(1, _int(os.getenv("DB_SYNC_TIME"), 5)),
        data_dir=data_dir,
        compose_dir=compose,
        subnets_path=subnets,
    )
