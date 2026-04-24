from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


class KevPluginService:
    """Read-only service for the `/kev plugin <pluginid>` command."""

    _PLUGIN_DETAIL_SQL = """
SELECT DISTINCT
  s.host,
  s.synopsis,
  s.cvss,
  k.cve_id AS cve,
  k.required_action,
  k.short_description,
  k.vendor_project,
  k.product,
  k.due_date,
  k.known_ransomware_campaign_use AS ransomware_flag,
  k.vulnerability_name
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

    # CISA boilerplate to strip from required_action
    _CISA_BOILERPLATE = re.compile(
        r"^Apply mitigations per vendor instructions"
        r"(?:, follow applicable BOD \d+-\d+ guidance for cloud services)?"
        r", or discontinue use of the product if (?:mitigations|updates) are unavailable\.",
        re.IGNORECASE,
    )

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
                "vulnerability_name": first.get("vulnerability_name"),
            }
        else:
            # Fallback for tuple rows (index-based)
            # Column order: host, synopsis, cvss, cve, required_action,
            #   short_description, vendor_project, product, due_date,
            #   ransomware_flag, vulnerability_name
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
                "vulnerability_name": first[10] if len(first) > 10 else None,
            }

        return hosts, detail

    def _clean_required_action(self, required_action: str) -> str:
        """Strip CISA boilerplate, keep specific actionable text.

        Returns cleaned text (max ~80 chars). If just boilerplate, returns
        the generic fallback: "Update or discontinue use per vendor instructions."
        """
        text = str(required_action).strip()
        if not text:
            return ""

        # Strip the known boilerplate prefix
        cleaned = self._CISA_BOILERPLATE.sub("", text).strip()

        # If nothing remains after stripping (just boilerplate), use fallback
        if not cleaned:
            return "Update or discontinue use per vendor instructions."

        # Trim to ~80 chars, breaking at word boundaries
        if len(cleaned) > 85:
            trimmed = cleaned[:85]
            last_space = trimmed.rfind(" ")
            if last_space > 60:
                cleaned = trimmed[:last_space]
            else:
                cleaned = trimmed.rstrip(".,; ")

        return cleaned

    def _build_vuln_line(self, detail: Dict[str, Optional[str]]) -> str:
        """Build the Vuln: line from vulnerability_name or short_description."""
        vuln_name = detail.get("vulnerability_name")

        if vuln_name and str(vuln_name).strip():
            return str(vuln_name).strip()

        # Fallback to short_description (first 120 chars)
        short = detail.get("short_description")
        if short and str(short).strip():
            text = str(short).strip()
            if len(text) > 120:
                trimmed = text[:120]
                last_space = trimmed.rfind(" ")
                if last_space > 80:
                    text = trimmed[:last_space]
                else:
                    text = trimmed.rstrip(".,; ")
            return text

        return ""

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

        # Fix line (heuristic: strip CISA boilerplate)
        required = detail.get("required_action")
        clean_fix = self._clean_required_action(required) if required else ""
        if clean_fix:
            lines.append(f"Fix: {clean_fix}")

        # Vuln line (new: use vulnerability_name or fallback to short_description)
        vuln_line = self._build_vuln_line(detail)
        if vuln_line:
            lines.append(f"Vuln: {vuln_line}")

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
