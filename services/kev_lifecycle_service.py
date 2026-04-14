from __future__ import annotations

from typing import Any


class KevLifecycleService:
    """Service for lifecycle commands such as `/kev close <pluginid>` and `/kev reopen <pluginid>`."""

    _CLOSE_SQL = """
INSERT INTO plugin_status (
  pluginid,
  status_key,
  status_update
) VALUES (
  %s,
  2,
  NOW()
)
ON DUPLICATE KEY UPDATE
  status_key = 2,
  status_update = NOW()
""".strip()

    _REOPEN_SQL = """
INSERT INTO plugin_status (
  pluginid,
  status_key,
  status_update
) VALUES (
  %s,
  1,
  NOW()
)
ON DUPLICATE KEY UPDATE
  status_key = 1,
  status_update = NOW()
""".strip()

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def close(self, pluginid: str) -> str:
        normalized_pluginid = self._normalize_pluginid(pluginid)
        self._cursor.execute(self._CLOSE_SQL, (int(normalized_pluginid),))
        return f"Plugin closed: pluginid={normalized_pluginid}, status_key=2"

    def reopen(self, pluginid: str) -> str:
        normalized_pluginid = self._normalize_pluginid(pluginid)
        self._cursor.execute(self._REOPEN_SQL, (int(normalized_pluginid),))
        return f"Plugin reopened: pluginid={normalized_pluginid}, status_key=1"

    def _normalize_pluginid(self, pluginid: str) -> str:
        value = str(pluginid or "").strip()
        if not value:
            raise ValueError("pluginid is required.")
        if not value.isdigit():
            raise ValueError("pluginid must be numeric.")
        return value
