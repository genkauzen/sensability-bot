from __future__ import annotations

# Зафиксированные параметры создания ВМ (не настраиваются через .env)
TWC_PRESET_ID = 4795
TWC_OS_ID = 99
TWC_BANDWIDTH = 1000

# Для POST /api/v1/servers: зона доступности + регион (location), иначе бэкенд
# валидирует location_zone и отклоняет, например, spb-3 без подходящего location.
_AVAIL_TO_LOCATION: dict[str, str] = {
    "msk-1": "ru-1",
    "spb-1": "ru-2",
    "spb-3": "ru-2",
    "spb-4": "ru-2",
    "nsk-1": "ru-3",
    "ams-1": "nl-1",
    "fra-1": "de-1",
    "ala-1": "kz-1",
    "ru-1": "ru-1",
    "ru-2": "ru-2",
    "ru-3": "ru-3",
}


def location_for_availability_zone(zone: str) -> str | None:
    """Регион Timeweb (ru-1 / ru-2 / …) для поля location в теле создания сервера."""
    z = (zone or "").strip().lower()
    if z in _AVAIL_TO_LOCATION:
        return _AVAIL_TO_LOCATION[z]
    if z.startswith("spb-"):
        return "ru-2"
    if z.startswith("msk-"):
        return "ru-1"
    return None


def create_server_network_for_public_ipv4() -> dict:
    """Один запрос на создание: явно запрашиваем публичный (floating) IPv4 в сети ВМ."""
    return {"floating_ip": True}
