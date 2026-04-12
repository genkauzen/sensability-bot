from __future__ import annotations

# Зафиксированные параметры создания ВМ (не настраиваются через .env)
TWC_PRESET_ID = 4795
TWC_OS_ID = 99
TWC_BANDWIDTH = 1000

# При балансе строго выше этого порога (в рублях) перебор идёт через плавающие IPv4, а не через ВМ.
TWC_FLOAT_IP_BALANCE_THRESHOLD_RUB = 179.0

# Зоны плавающего IPv4 по умолчанию (СПб); смена без перезапуска: /timeweb mng -ip …
TWC_FLOAT_IP_ZONES: tuple[str, ...] = ("spb-3",)
TWC_FLOAT_IP_ZONES_DB_KEY = "twc_float_ip_zones"

# Пауза перебора после «лимита месяца» / недостатка средств на месяц (секунды).
TWC_MONTH_LIMIT_COOLDOWN_SEC = 86400
