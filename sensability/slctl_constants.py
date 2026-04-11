from __future__ import annotations

# Пауза перебора после 429 / аналогичных ограничений API (секунды).
SLCTL_RATE_COOLDOWN_SEC = 1800

# Дополнительные CIDR для проверки «ПНА» у Selectel (мобильный whitelist + локальные подсети).
DEFAULT_SLCTL_EXTRA_CIDR_URL = (
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/"
    "refs/heads/main/cidrwhitelist.txt"
)
