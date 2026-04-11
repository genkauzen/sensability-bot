from __future__ import annotations

import base64
import json


def jwt_payload_unverified(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    pad = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + pad)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return {}
