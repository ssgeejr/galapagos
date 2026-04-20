from __future__ import annotations

from typing import Any


class KevTicketService:
    """Service for `/kev ticket ...` commands."""

    _SELECT_PLUGIN_STATUS_SQL = """
SELECT
  pluginid,
  ticketid
FROM plugin_status
WHERE pluginid = %s
LIMIT 1
""".strip()

    _INSERT_PLUGIN_STATUS_SQL = """
INSERT INTO plugin_status (
  pluginid,
  ticketid,
  status_update
) VALUES (
  %s,
  %s,
  NOW()
)
""".strip()

    _UPDATE_TICKET_SQL = """
UPDATE plugin_status
SET ticketid = %s,
    status_update = NOW()
WHERE pluginid = %s
  AND (ticketid IS NULL OR ticketid = '')
""".strip()

    _UPDATE_STATUS_BY_PLUGIN_SQL = """
UPDATE plugin_status
SET status_key = %s,
    status_update = NOW()
WHERE pluginid = %s
""".strip()

    _UPDATE_STATUS_BY_TICKET_SQL = """
UPDATE plugin_status
SET status_key = %s,
    status_update = NOW()
WHERE ticketid = %s
""".strip()

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def add_ticket(self, pluginid: str, ticketid: str) -> str:
        normalized_pluginid = self._normalize_pluginid(pluginid)
        normalized_ticketid = self._normalize_ticketid(ticketid)

        row = self._fetch_plugin_status(normalized_pluginid)
        if row is None:
            self._cursor.execute(
                self._INSERT_PLUGIN_STATUS_SQL,
                (int(normalized_pluginid), normalized_ticketid),
            )
            return f"Linked ticket {normalized_ticketid} to plugin {normalized_pluginid}."

        existing_ticket = str(row.get("ticketid") or "").strip()
        if existing_ticket:
            return f"Plugin {normalized_pluginid} already has ticket {existing_ticket}. No change made."

        self._cursor.execute(
            self._UPDATE_TICKET_SQL,
            (normalized_ticketid, int(normalized_pluginid)),
        )
        return f"Linked ticket {normalized_ticketid} to plugin {normalized_pluginid}."

    def update_by_plugin(self, pluginid: str, state: str) -> str:
        normalized_pluginid = self._normalize_pluginid(pluginid)
        status_key, status_name = self._normalize_state(state)
        self._cursor.execute(
            self._UPDATE_STATUS_BY_PLUGIN_SQL,
            (status_key, int(normalized_pluginid)),
        )
        if int(getattr(self._cursor, "rowcount", 0)) == 0:
            return f"No status row found for plugin {normalized_pluginid}. No change made."
        return f"Updated plugin {normalized_pluginid} to {status_name}."

    def update_by_ticket(self, ticketid: str, state: str) -> str:
        normalized_ticketid = self._normalize_ticketid(ticketid)
        status_key, status_name = self._normalize_state(state)
        self._cursor.execute(
            self._UPDATE_STATUS_BY_TICKET_SQL,
            (status_key, normalized_ticketid),
        )
        changed = int(getattr(self._cursor, "rowcount", 0))
        if changed == 0:
            return f"No status row found for ticket {normalized_ticketid}. No change made."
        return f"Updated ticket {normalized_ticketid} to {status_name}."

    def _normalize_pluginid(self, pluginid: str) -> str:
        value = str(pluginid or "").strip()
        if not value:
            raise ValueError("pluginid is required.")
        if not value.isdigit():
            raise ValueError("pluginid must be numeric.")
        return value

    def _normalize_ticketid(self, ticketid: str) -> str:
        value = str(ticketid or "").strip()
        if not value:
            raise ValueError("ticket# is required.")
        return value

    def _normalize_state(self, state: str) -> tuple[int, str]:
        value = str(state or "").strip().lower()
        if value in {"1", "open"}:
            return 1, "open"
        if value in {"2", "closed", "close"}:
            return 2, "closed"
        raise ValueError("state must be one of: open, closed, 1, 2.")

    def _fetch_plugin_status(self, pluginid: str) -> dict[str, Any] | None:
        self._cursor.execute(self._SELECT_PLUGIN_STATUS_SQL, (int(pluginid),))
        row = self._cursor.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return row
        return {"pluginid": row[0], "ticketid": row[1]}
