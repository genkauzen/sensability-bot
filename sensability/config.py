from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from sensability.slctl_constants import (
    DEFAULT_SLCTL_EXTRA_CIDR_URL,
    DEFAULT_SLCTL_FLOAT_REGIONS,
)

# Файлы whitelist IPv4 по умолчанию (корень репозитория или смонтированный /compose в Docker).
DEFAULT_TIMEWEB_SUBNETS_FILENAME = "timewebcloud_subnets.txt"
DEFAULT_SELECTEL_SUBNETS_FILENAME = "selectel_subnets.txt"
DEFAULT_REGRU_SUBNETS_FILENAME = "regru_subnets.txt"


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


def _csv_region_list(v: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = (v or "").strip()
    if not raw:
        return default
    parts = tuple(x.strip() for x in raw.split(",") if x.strip())
    return parts if parts else default


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
    twc_atmoment_acc: int
    twc_minimum_rubles: float
    twc_vm_alivetime_minutes: int
    db_sync_time_minutes: int
    slctl_proxy_use: bool
    slctl_proxy_url: str | None
    slctl_ip_location: str
    slctl_atmoment_acc: int
    slctl_minimum_rubles: float
    slctl_whitelist_cidr_url: str | None
    slctl_flavor_id: str | None
    slctl_image_id: str | None
    slctl_network_uuid: str | None
    slctl_billing_x_token: str | None
    slctl_float_regions: tuple[str, ...]
    regru_atmoment_acc: int
    regru_minimum_rubles: float
    data_dir: Path
    compose_dir: Path
    timeweb_subnets_path: Path
    selectel_subnets_path: Path
    regru_subnets_path: Path
    regru_region: str


def _resolve_compose_dir(package_root: Path) -> Path:
    override = (os.getenv("SENSABILITY_COMPOSE_DIR") or "").strip()
    if override:
        p = Path(override)
        if p.is_dir() and (p / "docker-compose.yml").is_file():
            return p.resolve()
    candidates = [
        Path("/compose"),
        package_root,
        Path.cwd(),
    ]
    for p in candidates:
        try:
            if p.is_dir() and (p / "docker-compose.yml").is_file():
                return p.resolve()
        except OSError:
            continue
    return package_root


def _subnet_file_override_only(env_primary: str, env_legacy: str | None) -> Path | None:
    """Явный путь из переменных окружения (без автопоиска)."""
    raw = (os.getenv(env_primary) or "").strip()
    if not raw and env_legacy:
        raw = (os.getenv(env_legacy) or "").strip()
    return Path(raw).expanduser() if raw else None


def resolve_subnet_file(base_dir: Path, filename: str, *, explicit: Path | None) -> Path:
    """Файл whitelist-подсетей: явный env или файл в директории приложения."""
    if explicit is not None:
        return explicit.resolve()
    return (base_dir / filename).resolve()


def load_config() -> Config:
    load_dotenv()
    data_dir = Path(os.getenv("SENSABILITY_DATA_DIR", "/app/data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    package_parent = Path(__file__).resolve().parent.parent
    compose = _resolve_compose_dir(package_parent)
    tw_explicit = _subnet_file_override_only("SENSABILITY_TWC_SUBNETS_PATH", "SENSABILITY_SUBNETS_PATH")
    sl_explicit = _subnet_file_override_only("SENSABILITY_SLCTL_SUBNETS_PATH", None)
    rg_explicit = _subnet_file_override_only("SENSABILITY_REGRU_SUBNETS_PATH", None)
    # По умолчанию читаем *.txt рядом с приложением (WORKDIR=/app).
    timeweb_subnets = resolve_subnet_file(package_parent, DEFAULT_TIMEWEB_SUBNETS_FILENAME, explicit=tw_explicit)
    selectel_subnets = resolve_subnet_file(package_parent, DEFAULT_SELECTEL_SUBNETS_FILENAME, explicit=sl_explicit)
    regru_subnets = resolve_subnet_file(package_parent, DEFAULT_REGRU_SUBNETS_FILENAME, explicit=rg_explicit)

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
        twc_vm_region=(os.getenv("TWC_VM_REGION") or "").strip(),
        twc_atmoment_acc=max(1, _int(os.getenv("TWC_ATMOMENT_ACC"), 3)),
        twc_minimum_rubles=_float(os.getenv("TWC_MINIMUM_RUBLES"), 0.0),
        twc_vm_alivetime_minutes=max(1, _int(os.getenv("TWC_VM_ALIVETIME"), 5)),
        db_sync_time_minutes=max(1, _int(os.getenv("DB_SYNC_TIME"), 5)),
        slctl_proxy_use=_bool(os.getenv("SLCTL_PROXY_USE"), False),
        slctl_proxy_url=(os.getenv("SLCTL_PROXY_URL") or "").strip() or None,
        slctl_ip_location=(os.getenv("SLCTL_IP_LOCATION") or "ru-7").strip(),
        slctl_atmoment_acc=max(1, _int(os.getenv("SLCTL_ATMOMENT_ACC"), 2)),
        slctl_minimum_rubles=_float(os.getenv("SLCTL_MINIMUM_RUBLES"), 0.0),
        slctl_whitelist_cidr_url=(os.getenv("SLCTL_WHITELIST_CIDR_URL") or "").strip()
        or DEFAULT_SLCTL_EXTRA_CIDR_URL,
        slctl_flavor_id=(os.getenv("SLCTL_FLAVOR_ID") or "").strip() or None,
        slctl_image_id=(os.getenv("SLCTL_IMAGE_ID") or "").strip() or None,
        slctl_network_uuid=(os.getenv("SLCTL_NETWORK_UUID") or "").strip() or None,
        slctl_billing_x_token=(os.getenv("SLCTL_BILLING_X_TOKEN") or "").strip() or None,
        slctl_float_regions=_csv_region_list(
            os.getenv("SLCTL_FLOAT_REGIONS"),
            DEFAULT_SLCTL_FLOAT_REGIONS,
        ),
        regru_atmoment_acc=max(1, _int(os.getenv("REGRU_ATMOMENT_ACC"), 4)),
        regru_minimum_rubles=_float(os.getenv("REGRU_MINIMUM_RUBLES"), 0.0),
        data_dir=data_dir,
        compose_dir=compose,
        timeweb_subnets_path=timeweb_subnets,
        selectel_subnets_path=selectel_subnets,
        regru_subnets_path=regru_subnets,
        regru_region=(os.getenv("REGRU_REGION") or "openstack-msk1").strip(),
    )
