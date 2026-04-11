from __future__ import annotations

# Зафиксированные параметры создания ВМ (не настраиваются через .env)
TWC_PRESET_ID = 4795
TWC_OS_ID = 99
TWC_BANDWIDTH = 1000

# При балансе строго выше этого порога (в рублях) перебор идёт через плавающие IPv4, а не через ВМ.
TWC_FLOAT_IP_BALANCE_THRESHOLD_RUB = 179.0

# Зоны для заказа плавающего IP (сначала spb-3, при ошибке — msk-1).
TWC_FLOAT_IP_ZONES: tuple[str, ...] = ("spb-3", "msk-1")

# Пауза перебора после «лимита месяца» / недостатка средств на месяц (секунды).
TWC_MONTH_LIMIT_COOLDOWN_SEC = 86400
