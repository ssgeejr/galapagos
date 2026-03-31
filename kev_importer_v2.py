#!/usr/bin/env python3
"""
KEV Importer V2

Purpose
-------
- Fetch the current CISA KEV catalog
- Compare it to the current/latest KEV xref set
- Upsert into kev_item
- Rebuild kev_xref as the current/live KEV list
- Build today's daily_kev_top20 from the latest Tenable dtkey
- Hard-exit if today's file has already been loaded

Config
------
Reads MySQL credentials from:
    ~/.neurosentinel/db.conf

Expected config format
----------------------
[mysql]
host = localhost
port = 3306
user = your_username
password = your_password
database = your_database
"""

from __future__ import annotations

import argparse
import configparser
import json
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

import mysql.connector
from mysql.connector import Error


@dataclass
class KevSummary:
    total_feed_items: int
    current_xref_items_before: int
    new_cves_vs_current_xref: int
    removed_cves_vs_current_xref: int
    kev_item_active_count: int
    top20_rows_inserted: int
    latest_dtkey: str


class KEVImporterV2:
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CONFIG_PATH = Path.home() / ".neurosentinel" / "db.conf"
    LOCAL_JSON_PATH = Path("kev.json")

    def __init__(self, no_update: bool = False, verbose: bool = True) -> None:
        self.no_update = no_update
        self.verbose = verbose
        self.db_config = self._load_db_config()
        self.conn = None
        self.cursor = None

    def log(self, message: str) -> None:
        if self.verbose:
            print(message)

    def _load_db_config(self) -> dict[str, Any]:
        config = configparser.ConfigParser()
        if not self.CONFIG_PATH.exists():
            raise FileNotFoundError(
                f"Database config not found: {self.CONFIG_PATH}\n"
                "Expected format:\n"
                "[mysql]\n"
                "host = localhost\n"
                "port = 3306\n"
                "user = your_username\n"
                "password = your_password\n"
                "database = your_database\n"
            )

        config.read(self.CONFIG_PATH)
        if "mysql" not in config:
            raise ValueError(f"[mysql] section missing in {self.CONFIG_PATH}")

        mysql_cfg = config["mysql"]
        return {
            "host": mysql_cfg.get("host", "localhost"),
            "port": mysql_cfg.getint("port", 3306),
            "user": mysql_cfg.get("user"),
            "password": mysql_cfg.get("password"),
            "database": mysql_cfg.get("database"),
        }

    def _connect_db(self) -> None:
        try:
            self.conn = mysql.connector.connect(**self.db_config)
            self.cursor = self.conn.cursor(dictionary=True)
            self.log("✅ Connected to MySQL.")
        except Error as exc:
            raise ConnectionError(f"Failed to connect to MySQL: {exc}") from exc

    def _close_db(self) -> None:
        if self.cursor:
            self.cursor.close()
        if self.conn and self.conn.is_connected():
            self.conn.close()
            self.log("🔒 Database connection closed.")

    def _check_already_loaded(self) -> None:
        """
        Hard stop if today's daily_kev_top20 already exists.
        """
        assert self.cursor is not None
        self.cursor.execute(
            """
            SELECT COUNT(*) AS row_count
            FROM daily_kev_top20
            WHERE run_date = CURDATE()
            """
        )
        row = self.cursor.fetchone()
        row_count = int(row["row_count"]) if row else 0

        if row_count > 0:
            today_str = datetime.now().strftime("%m/%d/%y")
            print(f"err: file already loaded for {today_str}", file=sys.stderr)
            sys.exit(1)

    def _load_feed_json(self) -> dict[str, Any]:
        if self.no_update:
            if not self.LOCAL_JSON_PATH.exists():
                raise FileNotFoundError(
                    "No local kev.json found. Run without --noupdate first or place kev.json in the current directory."
                )
            self.log("ℹ️ Using local kev.json (--noupdate)")
            with self.LOCAL_JSON_PATH.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        else:
            self.log(f"📥 Fetching KEV catalog from {self.KEV_URL} ...")
            try:
                with urllib.request.urlopen(self.KEV_URL, timeout=30) as response:
                    raw = response.read()
                data = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                raise RuntimeError(f"Failed to fetch KEV JSON: {exc}") from exc

            if "vulnerabilities" not in data:
                raise ValueError("Invalid KEV JSON: missing 'vulnerabilities' key")

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".tmp", delete=False, dir=".", encoding="utf-8"
            ) as tmp:
                json.dump(data, tmp, indent=2)
                tmp_path = Path(tmp.name)

            tmp_path.replace(self.LOCAL_JSON_PATH)
            self.log(f"✅ Saved KEV feed to {self.LOCAL_JSON_PATH}")

        return data

    @staticmethod
    def _to_date(value: str | None) -> str | None:
        if not value:
            return None
        return value

    @staticmethod
    def _ransomware_flag(value: str | None) -> int:
        return 1 if value == "Known" else 0

    def _normalize_feed(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()

        for item in data.get("vulnerabilities", []):
            cve_id = (item.get("cveID") or "").strip()
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)

            normalized.append(
                {
                    "cve_id": cve_id,
                    "vendor_project": item.get("vendorProject") or None,
                    "product": item.get("product") or None,
                    "vulnerability_name": item.get("vulnerabilityName") or None,
                    "date_added": self._to_date(item.get("dateAdded")),
                    "due_date": self._to_date(item.get("dueDate")),
                    "short_description": item.get("shortDescription") or None,
                    "required_action": item.get("requiredAction") or None,
                    "notes": item.get("notes") or None,
                    "known_ransomware_campaign_use": self._ransomware_flag(
                        item.get("knownRansomwareCampaignUse")
                    ),
                }
            )

        return normalized

    def _get_current_xref_cves(self) -> set[str]:
        assert self.cursor is not None
        self.cursor.execute("SELECT cve_id FROM kev_xref")
        rows = self.cursor.fetchall()
        return {str(r["cve_id"]) for r in rows}

    def _upsert_kev_item(self, feed_rows: list[dict[str, Any]]) -> None:
        assert self.cursor is not None
        today = date.today().isoformat()

        sql = """
        INSERT INTO kev_item (
            cve_id,
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            due_date,
            short_description,
            required_action,
            notes,
            known_ransomware_campaign_use,
            first_seen_date,
            last_seen_date,
            is_active
        )
        VALUES (
            %(cve_id)s,
            %(vendor_project)s,
            %(product)s,
            %(vulnerability_name)s,
            %(date_added)s,
            %(due_date)s,
            %(short_description)s,
            %(required_action)s,
            %(notes)s,
            %(known_ransomware_campaign_use)s,
            %(first_seen_date)s,
            %(last_seen_date)s,
            1
        )
        ON DUPLICATE KEY UPDATE
            vendor_project = VALUES(vendor_project),
            product = VALUES(product),
            vulnerability_name = VALUES(vulnerability_name),
            date_added = VALUES(date_added),
            due_date = VALUES(due_date),
            short_description = VALUES(short_description),
            required_action = VALUES(required_action),
            notes = VALUES(notes),
            known_ransomware_campaign_use = VALUES(known_ransomware_campaign_use),
            last_seen_date = VALUES(last_seen_date),
            is_active = 1
        """

        payload = []
        for row in feed_rows:
            record = dict(row)
            record["first_seen_date"] = today
            record["last_seen_date"] = today
            payload.append(record)

        self.cursor.executemany(sql, payload)
        self.log(f"🔄 Upserted {len(payload)} rows into kev_item.")

    def _mark_inactive_missing_cves(self, feed_cves: set[str]) -> None:
        assert self.cursor is not None
        if not feed_cves:
            raise RuntimeError("Refusing to mark kev_item inactive because the current KEV feed is empty.")

        placeholders = ", ".join(["%s"] * len(feed_cves))
        sql = f"""
        UPDATE kev_item
        SET is_active = 0
        WHERE cve_id NOT IN ({placeholders})
        """
        self.cursor.execute(sql, tuple(sorted(feed_cves)))
        self.log(f"🔕 Marked missing CVEs inactive in kev_item ({self.cursor.rowcount} rows affected).")

    def _rebuild_kev_xref(self, feed_cves: set[str]) -> None:
        assert self.cursor is not None
        if not feed_cves:
            raise RuntimeError("Refusing to rebuild kev_xref because the current KEV feed is empty.")

        placeholders = ", ".join(["%s"] * len(feed_cves))

        self.cursor.execute("TRUNCATE TABLE kev_xref")
        self.log("🧹 Truncated kev_xref.")

        insert_sql = f"""
        INSERT INTO kev_xref (
            kev_item_id,
            cve_id,
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            due_date,
            short_description,
            required_action,
            notes,
            known_ransomware_campaign_use
        )
        SELECT
            kev_item_id,
            cve_id,
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            due_date,
            short_description,
            required_action,
            notes,
            known_ransomware_campaign_use
        FROM kev_item
        WHERE cve_id IN ({placeholders})
          AND is_active = 1
        """
        self.cursor.execute(insert_sql, tuple(sorted(feed_cves)))
        self.log(f"♻️ Rebuilt kev_xref with {self.cursor.rowcount} current rows.")

    def _get_latest_dtkey(self) -> str:
        assert self.cursor is not None
        self.cursor.execute(
            """
            SELECT dtkey
            FROM scorecard
            ORDER BY rptdate DESC
            LIMIT 1
            """
        )
        row = self.cursor.fetchone()
        if not row or not row.get("dtkey"):
            raise RuntimeError("Could not determine latest dtkey from scorecard.")
        return str(row["dtkey"])

    def _build_daily_top20(self, dtkey: str) -> int:
        assert self.cursor is not None

        delete_sql = """
        DELETE FROM daily_kev_top20
        WHERE run_date = CURDATE()
        """
        self.cursor.execute(delete_sql)

        insert_sql = """
        INSERT INTO daily_kev_top20 (
            run_date,
            dtkey,
            pluginid,
            solution,
            hosts,
            ransomware_flag,
            priority_score,
            risk_rank
        )
        SELECT
            CURDATE() AS run_date,
            %s AS dtkey,
            ranked.pluginid,
            ranked.solution,
            ranked.hosts,
            ranked.ransomware_flag,
            ranked.priority_score,
            ranked.risk_rank
        FROM (
            SELECT
                agg.pluginid,
                agg.solution,
                agg.hosts,
                agg.ransomware_flag,
                agg.priority_score,
                ROW_NUMBER() OVER (
                    ORDER BY agg.priority_score DESC, agg.hosts DESC, agg.pluginid
                ) AS risk_rank
            FROM (
                SELECT
                    s.pluginid,
                    s.solution,
                    COUNT(DISTINCT s.host) AS hosts,
                    MAX(k.known_ransomware_campaign_use) AS ransomware_flag,
                    COUNT(DISTINCT s.host) +
                        (CASE WHEN MAX(k.known_ransomware_campaign_use) = 1 THEN 100 ELSE 0 END) AS priority_score
                FROM scorecard s
                INNER JOIN kev_xref k
                    ON k.cve_id = s.cve
                WHERE s.dtkey = %s
                  AND s.kev_flag = 1
                GROUP BY s.pluginid, s.solution
            ) agg
        ) ranked
        WHERE ranked.risk_rank <= 20
        ORDER BY ranked.risk_rank
        """
        self.cursor.execute(insert_sql, (dtkey, dtkey))
        self.log(f"📊 Inserted {self.cursor.rowcount} rows into daily_kev_top20.")
        return int(self.cursor.rowcount)

    def _count_active_kev_items(self) -> int:
        assert self.cursor is not None
        self.cursor.execute("SELECT COUNT(*) AS cnt FROM kev_item WHERE is_active = 1")
        row = self.cursor.fetchone()
        return int(row["cnt"]) if row else 0

    def _fetch_today_top20(self) -> list[dict[str, Any]]:
        assert self.cursor is not None
        self.cursor.execute(
            """
            SELECT
                risk_rank,
                pluginid,
                hosts,
                ransomware_flag,
                priority_score,
                solution
            FROM daily_kev_top20
            WHERE run_date = CURDATE()
            ORDER BY risk_rank
            """
        )
        return list(self.cursor.fetchall())

    def _print_status(self, summary: KevSummary) -> None:
        status = (
            f"loaded={summary.total_feed_items}; "
            f"new_vs_current={summary.new_cves_vs_current_xref}; "
            f"removed_vs_current={summary.removed_cves_vs_current_xref}; "
            f"active={summary.kev_item_active_count}; "
            f"top20={summary.top20_rows_inserted}; "
            f"dtkey={summary.latest_dtkey}"
        )
        print(f"[TO TEAMS==> KEV Status --> {status}]")

    def _print_top20(self) -> None:
        rows = self._fetch_today_top20()
        if not rows:
            print("No top 20 rows found for today.")
            return

        print("")
        print("Current KEV Top 20")
        print("-" * 120)
        print(f"{'Rank':<6} {'PluginID':<12} {'Hosts':<8} {'Ransom':<8} {'Priority':<10} Solution")
        print("-" * 120)
        for row in rows:
            solution = (row.get("solution") or "").replace("\n", " ").strip()
            if len(solution) > 72:
                solution = solution[:69] + "..."
            print(
                f"{str(row.get('risk_rank', '')):<6} "
                f"{str(row.get('pluginid', '')):<12} "
                f"{str(row.get('hosts', '')):<8} "
                f"{str(row.get('ransomware_flag', '')):<8} "
                f"{str(row.get('priority_score', '')):<10} "
                f"{solution}"
            )

    def run(self) -> None:
        self._connect_db()
        try:
            self._check_already_loaded()

            data = self._load_feed_json()
            feed_rows = self._normalize_feed(data)
            if not feed_rows:
                raise RuntimeError("KEV feed returned zero vulnerabilities.")

            feed_cves = {row["cve_id"] for row in feed_rows}
            current_xref_cves = self._get_current_xref_cves()

            self.conn.start_transaction()

            self._upsert_kev_item(feed_rows)
            self._mark_inactive_missing_cves(feed_cves)
            self._rebuild_kev_xref(feed_cves)

            latest_dtkey = self._get_latest_dtkey()
            top20_count = self._build_daily_top20(latest_dtkey)

            self.conn.commit()

            summary = KevSummary(
                total_feed_items=len(feed_rows),
                current_xref_items_before=len(current_xref_cves),
                new_cves_vs_current_xref=len(feed_cves - current_xref_cves),
                removed_cves_vs_current_xref=len(current_xref_cves - feed_cves),
                kev_item_active_count=self._count_active_kev_items(),
                top20_rows_inserted=top20_count,
                latest_dtkey=latest_dtkey,
            )
            self._print_status(summary)
            self._print_top20()

        except Exception:
            if self.conn:
                self.conn.rollback()
            raise
        finally:
            self._close_db()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="KEV Importer V2")
    parser.add_argument(
        "--noupdate",
        action="store_true",
        help="Skip fetching fresh KEV JSON and use local kev.json",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        importer = KEVImporterV2(no_update=args.noupdate)
        importer.run()
    except SystemExit:
        raise
    except Exception as exc:
        print(f"❌ Fatal error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
