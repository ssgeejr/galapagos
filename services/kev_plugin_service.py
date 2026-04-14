from __future__ import annotations

from typing import Any


class KevPluginService:
    """Read-only service for the `/kev plugin <pluginid>` command."""

    _PLUGIN_HOSTS_SQL = """
SELECT DISTINCT
  host
FROM scorecard
WHERE dtkey = (
  SELECT dtkey
  FROM scorecard
  WHERE kev_flag = 1
  ORDER BY
    SUBSTR(dtkey, 3, 2) DESC,
    SUBSTR(dtkey, 1, 2) DESC,
    SUBSTR(dtkey, 5, 1) DESC
  LIMIT 1
)
AND kev_flag = 1
AND pluginid = %s
ORDER BY host
""".strip()

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def run(self, pluginid: str) -> str:
        """Fetch all affected hosts for pluginid on the latest dtkey snapshot."""
        normalized_pluginid = self._normalize_pluginid(pluginid)
        hosts = self._fetch_hosts(normalized_pluginid)
        return self._format_table(normalized_pluginid, hosts)

    def _normalize_pluginid(self, pluginid: str) -> str:
        value = str(pluginid or "").strip()
        if not value:
            raise ValueError("pluginid is required.")
        return value

    def _fetch_hosts(self, pluginid: str) -> list[str]:
        self._cursor.execute(self._PLUGIN_HOSTS_SQL, (pluginid,))
        rows = self._cursor.fetchall() or []

        hosts: list[str] = []
        for row in rows:
            if isinstance(row, dict):
                host = row.get("host")
            else:
                host = row[0] if row else None

            host_text = str(host or "").strip()
            if host_text:
                hosts.append(host_text)

        return hosts

    def _format_table(self, pluginid: str, hosts: list[str]) -> str:
        if not hosts:
            return f"No hosts found for pluginid {pluginid} on latest dtkey."

        columns = ["#", "Host"]
        table_rows = [[str(i), host] for i, host in enumerate(hosts, start=1)]

        widths = [len(columns[0]), len(columns[1])]
        for row in table_rows:
            if len(row[0]) > widths[0]:
                widths[0] = len(row[0])
            if len(row[1]) > widths[1]:
                widths[1] = len(row[1])

        header = f"PluginID: {pluginid} | Hosts: {len(hosts)}"
        table_header = f"{columns[0].ljust(widths[0])} | {columns[1].ljust(widths[1])}"
        separator = f"{'-' * widths[0]}-+-{'-' * widths[1]}"
        body = [f"{row[0].ljust(widths[0])} | {row[1].ljust(widths[1])}" for row in table_rows]

        return "\n".join([header, table_header, separator, *body])
