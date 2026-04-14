from __future__ import annotations

from typing import Any


class KevStatusService:
    """Read-only service for the `/kev status <pluginid>` command."""

    _STATUS_SQL = """
SELECT
  ps.pluginid,
  ps.ticketid,
  ps.status_key,
  sx.status AS status_name,
  ps.status_update,
  ps.create_date
FROM plugin_status ps
LEFT JOIN status_xref sx
  ON sx.status_key = ps.status_key
WHERE ps.pluginid = %s
LIMIT 1
""".strip()

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def run(self, pluginid: str) -> str:
        normalized_pluginid = self._normalize_pluginid(pluginid)
        row = self._fetch_status(normalized_pluginid)
        return self._format_table(normalized_pluginid, row)

    def _normalize_pluginid(self, pluginid: str) -> str:
        value = str(pluginid or "").strip()
        if not value:
            raise ValueError("pluginid is required.")
        return value

    def _fetch_status(self, pluginid: str) -> dict[str, Any] | None:
        self._cursor.execute(self._STATUS_SQL, (pluginid,))
        row = self._cursor.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return row

        pluginid_val, ticketid, status_key, status_name, status_update, create_date = row
        return {
            "pluginid": pluginid_val,
            "ticketid": ticketid,
            "status_key": status_key,
            "status_name": status_name,
            "status_update": status_update,
            "create_date": create_date,
        }

    def _format_table(self, pluginid: str, row: dict[str, Any] | None) -> str:
        if not row:
            return f"No status record found for pluginid {pluginid}."

        status_name = str(row.get("status_name") or "unknown")
        ticketid = str(row.get("ticketid") or "")
        status_key = str(row.get("status_key") or "")
        status_update = str(row.get("status_update") or "")
        create_date = str(row.get("create_date") or "")

        columns = ["Field", "Value"]
        values = [
            ["PluginID", str(row.get("pluginid") or pluginid)],
            ["TicketID", ticketid if ticketid else "no-ticket-assigned"],
            ["StatusKey", status_key],
            ["Status", status_name],
            ["StatusMap", "1=open, 2=closed"],
            ["StatusUpdate", status_update if status_update else "(not set)"],
            ["CreateDate", create_date],
        ]

        widths = [len(columns[0]), len(columns[1])]
        for field, value in values:
            widths[0] = max(widths[0], len(field))
            widths[1] = max(widths[1], len(value))

        header = f"{columns[0].ljust(widths[0])} | {columns[1].ljust(widths[1])}"
        separator = f"{'-' * widths[0]}-+-{'-' * widths[1]}"
        body = [f"{field.ljust(widths[0])} | {value.ljust(widths[1])}" for field, value in values]

        return "\n".join([header, separator, *body])
