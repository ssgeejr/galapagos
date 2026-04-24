from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


class KevPluginService:
    """Read-only service for the `/kev plugin <pluginid>` command."""

    _PLUGIN_DETAIL_SQL = """
SELECT DISTINCT
  s.host,
  s.severity,
  s.cvss,
  k.cve_id AS cve,
  k.required_action,
  k.short_description,
  k.vendor_project,
  k.product,
  k.due_date,
  k.known_ransomware_campaign_use AS ransomware_flag
FROM scorecard s
LEFT JOIN kev_run_data k
  ON s.cve = k.cve_id
  AND k.kev_run_id = (
    SELECT kev_run_id
    FROM kev_run
    ORDER BY run_date DESC
    LIMIT 1
  )
WHERE s.dtkey = (
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
        hosts, detail = self._fetch_plugin_detail(normalized_pluginid)
        return self._format_output(normalized_pluginid, hosts, detail)

    def _normalize_pluginid(self, pluginid: str) -> str:
        value = str(pluginid or "").strip()
        if not value:
            raise ValueError("pluginid is required.")
        return value

    def _fetch_plugin_detail(
        self, pluginid: str
    ) -> Tuple[List[str], Dict[str, Optional[str]]]:
        self._cursor.execute(self._PLUGIN_DETAIL_SQL, (pluginid,))
        rows = self._cursor.fetchall() or []

        if not rows:
            return [], {}

        hosts: List[str] = []
        for row in rows:
            if isinstance(row, dict):
                host = row.get("host")
            else:
                host = row[0] if row else None

            host_text = str(host or "").strip()
            if host_text:
                hosts.append(host_text)

        # All rows share the same CVE/KEV info — pick the first row.
        first = rows[0]
        if isinstance(first, dict):
            detail = {
                "cve": first.get("cve"),
                "required_action": first.get("required_action"),
                "short_description": first.get("short_description"),
                "vendor_project": first.get("vendor_project"),
                "product": first.get("product"),
                "due_date": first.get("due_date"),
                "severity": first.get("severity"),
                "cvss": first.get("cvss"),
                "ransomware_flag": first.get("ransomware_flag"),
            }
        else:
            # Fallback for tuple rows (index-based)
            detail = {
                "cve": first[3] if len(first) > 3 else None,
                "required_action": first[4] if len(first) > 4 else None,
                "short_description": first[5] if len(first) > 5 else None,
                "vendor_project": first[6] if len(first) > 6 else None,
                "product": first[7] if len(first) > 7 else None,
                "due_date": first[8] if len(first) > 8 else None,
                "severity": first[1] if len(first) > 1 else None,
                "cvss": first[2] if len(first) > 2 else None,
                "ransomware_flag": first[9] if len(first) > 9 else None,
            }

        return hosts, detail

    def _format_output(
        self,
        pluginid: str,
        hosts: List[str],
        detail: Dict[str, Optional[str]],
    ) -> str:
        if not hosts:
            return f"No hosts found for pluginid {pluginid} on latest dtkey."

        lines: List[str] = []

        # Header: Plugin ID | CVE | Priority
        header_parts = [f"Plugin {pluginid}"]

        cve = detail.get("cve")
        if cve:
            header_parts.append(cve)

        # Priority: compute from ransomware_flag
        ransomware_flag = detail.get("ransomware_flag")
        if ransomware_flag is not None and str(ransomware_flag).strip():
            is_ransomware = str(ransomware_flag).strip() in ("1", "True", "true", 1)
            priority = 100 if is_ransomware else 0
        else:
            is_ransomware = False
            priority = 0

        header_parts.append(f"Priority: {priority}")
        header_parts.append(f"(ransomware: {'yes' if is_ransomware else 'no'})")

        lines.append(" | ".join(header_parts))
        lines.append("")

        # Fix line
        required = detail.get("required_action")
        short_desc = detail.get("short_description")
        if required or short_desc:
            fix_parts = []
            if required:
                fix_parts.append(str(required))
            if short_desc:
                fix_parts.append(f" — {short_desc}")
            lines.append(f"Fix: {' '.join(fix_parts)}")

        # Vendor line
        vendor_proj = detail.get("vendor_project")
        product = detail.get("product")
        if vendor_proj or product:
            parts = []
            if vendor_proj:
                parts.append(str(vendor_proj))
            if product:
                parts.append(str(product))
            lines.append(f"Vendor: {' '.join(parts)}")

        # CVE detail line
        sev = detail.get("severity")
        cvss = detail.get("cvss")
        due = detail.get("due_date")

        cve_parts = []
        if cve:
            cve_parts.append(f"CVE: {cve}")
        if sev:
            cve_parts.append(f"Severity: {sev}")
        if cvss is not None and str(cvss).strip():
            cve_parts.append(f"CVSS: {cvss}")
        if due is not None and str(due).strip():
            cve_parts.append(f"Due: {due}")
        if cve_parts:
            lines.append(" | ".join(cve_parts))

        # Blank line before hosts
        lines.append("")

        # Hosts
        lines.append(f"Affected hosts ({len(hosts)}):")
        lines.extend(f"- {host}" for host in hosts)

        return "\n".join(lines)
