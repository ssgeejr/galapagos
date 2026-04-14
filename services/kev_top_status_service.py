from __future__ import annotations

from typing import Any


class KevTopStatusService:
    """Read-only service for the `/kev top status` command."""

    _TOP_STATUS_SQL = """
WITH latest_status AS (
  SELECT
    ranked.pluginid,
    ranked.ticketid,
    ranked.status_key
  FROM (
    SELECT
      ps.pluginid,
      ps.ticketid,
      ps.status_key,
      ROW_NUMBER() OVER (
        PARTITION BY ps.pluginid
        ORDER BY COALESCE(ps.status_update, ps.create_date) DESC, ps.plugin_status_id DESC
      ) AS rn
    FROM plugin_status ps
  ) ranked
  WHERE ranked.rn = 1
)
SELECT
  t.risk_rank,
  t.pluginid,
  t.hosts,
  t.ransomware_flag,
  t.priority_score,
  COALESCE(ls.status_key, 1) AS status_key,
  COALESCE(sx.status, 'open') AS status_name,
  COALESCE(ls.ticketid, '') AS ticketid,
  t.solution
FROM daily_kev_top20 t
LEFT JOIN latest_status ls
  ON ls.pluginid = CAST(t.pluginid AS UNSIGNED)
LEFT JOIN status_xref sx
  ON sx.status_key = COALESCE(ls.status_key, 1)
WHERE t.run_date = CURDATE()
ORDER BY t.risk_rank
""".strip()

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def run(self) -> str:
        rows = self._fetch_rows()
        return self._format_table(rows)

    def _fetch_rows(self) -> list[dict[str, Any]]:
        self._cursor.execute(self._TOP_STATUS_SQL)
        raw_rows = self._cursor.fetchall() or []

        normalized: list[dict[str, Any]] = []
        for row in raw_rows:
            if isinstance(row, dict):
                data = dict(row)
            else:
                (
                    risk_rank,
                    pluginid,
                    hosts,
                    ransomware_flag,
                    priority_score,
                    status_key,
                    status_name,
                    ticketid,
                    solution,
                ) = row
                data = {
                    "risk_rank": risk_rank,
                    "pluginid": pluginid,
                    "hosts": hosts,
                    "ransomware_flag": ransomware_flag,
                    "priority_score": priority_score,
                    "status_key": status_key,
                    "status_name": status_name,
                    "ticketid": ticketid,
                    "solution": solution,
                }

            solution_text = str(data.get("solution") or "")
            data["solution"] = solution_text[:56]
            normalized.append(data)

        return normalized

    def _format_table(self, rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "No KEV top-status rows found for today."

        columns = ["Rank", "PluginID", "Hosts", "Ransom", "Priority", "SKey", "Status", "TicketID", "Solution"]
        table_rows: list[list[str]] = []
        for row in rows:
            table_rows.append(
                [
                    str(row.get("risk_rank") or ""),
                    str(row.get("pluginid") or ""),
                    str(row.get("hosts") or 0),
                    str(row.get("ransomware_flag") or 0),
                    str(row.get("priority_score") or 0),
                    str(row.get("status_key") or 1),
                    str(row.get("status_name") or "open"),
                    str(row.get("ticketid") or "no-ticket-assigned"),
                    str(row.get("solution") or ""),
                ]
            )

        widths = [len(h) for h in columns]
        for row in table_rows:
            for i, cell in enumerate(row):
                if len(cell) > widths[i]:
                    widths[i] = len(cell)

        header = " | ".join(columns[i].ljust(widths[i]) for i in range(len(columns)))
        separator = "-+-".join("-" * widths[i] for i in range(len(columns)))
        body = [
            " | ".join(row[i].ljust(widths[i]) for i in range(len(columns)))
            for row in table_rows
        ]
        return "\n".join([header, separator, *body])
