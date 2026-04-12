from __future__ import annotations

# Пауза перебора после 429 / аналогичных ограничений API (секунды).
SLCTL_RATE_COOLDOWN_SEC = 1800

# IAM-токен живёт до ~24 ч — обновляем заранее (секунды).
SLCTL_TOKEN_REFRESH_MAX_AGE_SEC = 20 * 3600

# Дополнительные CIDR для проверки «ПНА» у Selectel (мобильный whitelist + локальные подсети).
DEFAULT_SLCTL_EXTRA_CIDR_URL = (
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/"
    "refs/heads/main/cidrwhitelist.txt"
)

# Если Nova не отдаёт список flavor (пустой ответ и т.п.) — типичный минимальный flavor в публичном облаке Selectel (см. доку Terraform / KB).
DEFAULT_SLCTL_FLAVOR_FALLBACK = "1311"
