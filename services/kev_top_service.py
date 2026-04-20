from __future__ import annotations

from typing import Any


class KevTopService:
    """Read-only service for the `/kev top` command."""

    _TOP20_SQL = """
SELECT
  solution,
  pluginid,
  COUNT(DISTINCT host) AS hosts,
  MAX(kev_ransomware_flag) AS ransomware,
  COUNT(DISTINCT host) + (CASE WHEN MAX(kev_ransomware_flag) = 1 THEN 100 ELSE 0 END) AS priority_score
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
GROUP BY solution, pluginid
ORDER BY priority_score DESC, hosts DESC
LIMIT 20
""".strip()

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def run(self) -> str:
        """Execute the approved Top 20 query and return a formatted table."""
        rows = self._fetch_top20()
        return self._format_table(rows)

    def _fetch_top20(self) -> list[dict[str, Any]]:
        self._cursor.execute(self._TOP20_SQL)
        raw_rows = self._cursor.fetchall() or []

        normalized: list[dict[str, Any]] = []
        for row in raw_rows:
            if isinstance(row, dict):
                data = dict(row)
            else:
                # Supports tuple-style fetch results when not using DictCursor.
                solution, pluginid, hosts, ransomware, priority_score = row
                data = {
                    "solution": solution,
                    "pluginid": pluginid,
                    "hosts": hosts,
                    "ransomware": ransomware,
                    "priority_score": priority_score,
                }

            solution_text = str(data.get("solution") or "")
            data["solution"] = solution_text[:64]
            normalized.append(data)

        return normalized

    def _format_table(self, rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "No KEV top-20 results found."

        lines = [
            "KEV Top 20",
            "Ranked by priority score from the latest KEV snapshot.",
            "",
        ]
        for idx, row in enumerate(rows, start=1):
            ransomware = "yes" if str(row.get("ransomware") or "0") == "1" else "no"
            lines.append(
                f"{idx}. Plugin {row.get('pluginid') or ''} | "
                f"{row.get('hosts') or 0} host(s) | "
                f"ransomware: {ransomware} | "
                f"priority: {row.get('priority_score') or 0}"
            )
            solution = str(row.get("solution") or "").strip()
            if solution:
                lines.append(f"Solution: {solution}")

        return "\n".join(lines)
