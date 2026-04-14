#!/usr/bin/env python3
"""
KEV Importer V2

Purpose
-------
- Fetch the current CISA KEV catalog
- Insert one row into kev_run for the current execution date
- Insert the full KEV JSON snapshot into kev_run_data
- Compare the current run to the immediately previous run
- Insert only new KEV entries into kev_changes
- Build today's daily_kev_top20 from the latest Tenable dtkey
- Hard-exit if today's file has already been loaded

Data Model
----------
kev_run
    - One row per KEV import execution
    - Represents a single daily snapshot
    - Script checks this table first and refuses to run twice on the same day

kev_run_data
    - Full KEV catalog for that run
    - Foreign key to kev_run.kev_run_id

kev_changes
    - Contains only KEV items that are new in the current run
      compared to the immediately previous run
    - Foreign key to kev_run.kev_run_id
    - Stores kev_run_data_id values from the current run only
    - If no previous run exists, nothing is inserted here

daily_kev_top20
    - Stores the daily ranked top 20 KEV-related risks
    - Built from latest Tenable dtkey joined to current KEV run

plugin_status
    - Stores plugin tracking state for command workflows
    - Seeded from today's daily_kev_top20
    - Insert-only behavior during importer run (existing plugin rows are unchanged)

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

Execution Behavior
------------------
- Script terminates immediately if a record already exists in kev_run for today
- KEV data is fetched from CISA unless --noupdate is specified
- Local copy of KEV JSON is stored as kev.json
- All inserts occur in a single transaction
- On failure, transaction is rolled back
- On first run only, kev_changes remains empty because there is no previous run

Output
------
- Prints a Teams-compatible status line:
    [TO TEAMS==> KEV Status --> loaded=X; changes=Y; top20=Z; dtkey=A]

- Prints formatted Top 20 results to stdout
"""

from __future__ import annotations

import argparse
import configparser
import json
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import mysql.connector
from mysql.connector import Error


@dataclass
class KevSummary:
    total_feed_items: int
    changes_rows_inserted: int
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
        """
        Load MySQL settings from ~/.neurosentinel/db.conf.

        RawConfigParser is used so characters like % in passwords are not
        treated as interpolation markers.
        """
        config = configparser.RawConfigParser()

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
        """
        Open MySQL connection and dictionary cursor.
        """
        try:
            self.conn = mysql.connector.connect(**self.db_config)
            self.cursor = self.conn.cursor(dictionary=True)
            self.log("✅ Connected to MySQL.")
        except Error as exc:
            raise ConnectionError(f"Failed to connect to MySQL: {exc}") from exc

    def _close_db(self) -> None:
        """
        Close cursor and connection cleanly.
        """
        if self.cursor:
            self.cursor.close()
        if self.conn and self.conn.is_connected():
            self.conn.close()
            self.log("🔒 Database connection closed.")

    def _check_already_loaded(self) -> None:
        """
        Refuse to run if today's kev_run entry already exists.

        This is the hard stop that prevents the same day from being loaded twice.
        """
        assert self.cursor is not None

        self.cursor.execute(
            """
            SELECT COUNT(*) AS row_count
            FROM kev_run
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
        """
        Fetch KEV JSON from CISA or load local kev.json if --noupdate is used.

        A local copy is always written atomically when downloading fresh data.
        """
        if self.no_update:
            if not self.LOCAL_JSON_PATH.exists():
                raise FileNotFoundError(
                    "No local kev.json found. Run without --noupdate first or place kev.json in the current directory."
                )

            self.log("ℹ️ Using local kev.json (--noupdate)")
            with self.LOCAL_JSON_PATH.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data

        self.log(f"📥 Fetching KEV catalog from {self.KEV_URL}")

        try:
            with urllib.request.urlopen(self.KEV_URL, timeout=30) as response:
                raw = response.read()
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch KEV JSON: {exc}") from exc

        if "vulnerabilities" not in data:
            raise ValueError("Invalid KEV JSON: missing 'vulnerabilities' key")

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".tmp",
            delete=False,
            dir=".",
            encoding="utf-8",
        ) as tmp:
            json.dump(data, tmp, indent=2)
            tmp_path = Path(tmp.name)

        tmp_path.replace(self.LOCAL_JSON_PATH)
        self.log(f"✅ Saved KEV feed to {self.LOCAL_JSON_PATH}")

        return data

    @staticmethod
    def _to_date(value: str | None) -> str | None:
        """
        Keep date fields as strings acceptable to MySQL or None if blank.
        """
        if not value:
            return None
        return value

    @staticmethod
    def _ransomware_flag(value: str | None) -> int:
        """
        Convert KEV ransomware field into 1/0 integer.
        """
        return 1 if value == "Known" else 0

    def _normalize_feed(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Normalize raw KEV JSON into a clean, deduplicated list keyed by CVE.
        """
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

    def _insert_kev_run(self) -> int:
        """
        Insert one row into kev_run for today and return the new kev_run_id.
        """
        assert self.cursor is not None

        self.cursor.execute(
            """
            INSERT INTO kev_run (run_date)
            VALUES (CURDATE())
            """
        )

        kev_run_id = int(self.cursor.lastrowid)
        self.log(f"🗓️ Inserted kev_run_id={kev_run_id} for today.")
        return kev_run_id

    def _insert_kev_run_data(self, kev_run_id: int, feed_rows: list[dict[str, Any]]) -> None:
        """
        Insert the full normalized KEV feed into kev_run_data for the current run.
        """
        assert self.cursor is not None

        sql = """
        INSERT INTO kev_run_data (
            kev_run_id,
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
        VALUES (
            %(kev_run_id)s,
            %(cve_id)s,
            %(vendor_project)s,
            %(product)s,
            %(vulnerability_name)s,
            %(date_added)s,
            %(due_date)s,
            %(short_description)s,
            %(required_action)s,
            %(notes)s,
            %(known_ransomware_campaign_use)s
        )
        """

        payload: list[dict[str, Any]] = []
        for row in feed_rows:
            record = dict(row)
            record["kev_run_id"] = kev_run_id
            payload.append(record)

        self.cursor.executemany(sql, payload)
        self.log(f"📥 Inserted {len(payload)} rows into kev_run_data.")

    def _get_previous_run_id(self, current_run_id: int) -> int | None:
        """
        Return the immediately previous kev_run_id, not 'yesterday'.

        This allows for missed days or delayed runs without breaking the diff logic.
        """
        assert self.cursor is not None

        self.cursor.execute(
            """
            SELECT kev_run_id
            FROM kev_run
            WHERE kev_run_id < %s
            ORDER BY kev_run_id DESC
            LIMIT 1
            """,
            (current_run_id,),
        )

        row = self.cursor.fetchone()
        if not row:
            return None

        return int(row["kev_run_id"])

    def _insert_kev_updates(self, kev_run_id: int) -> int:
        """
        Update scorecard with KEV flags for the latest dtkey.

        Matches scorecard records to kev_run_data by CVE and applies
        kev_flag=1 and kev_ransomware_flag from the current KEV run.

        Returns the number of rows updated.
        """
        assert self.cursor is not None

        update_sql = """
        UPDATE scorecard s
        JOIN kev_run_data k
          ON s.cve = k.cve_id
        SET
          s.kev_flag = 1,
          s.kev_ransomware_flag = k.known_ransomware_campaign_use
        WHERE s.dtkey = (
          SELECT max_dtkey FROM (
            SELECT dtkey as max_dtkey
            FROM scorecard
            ORDER BY
              SUBSTR(dtkey, 3, 2) DESC,
              SUBSTR(dtkey, 1, 2) DESC,
              SUBSTR(dtkey, 5, 1) DESC
            LIMIT 1
          ) as subq
        )
        AND k.kev_run_id = %s
        """

        self.cursor.execute(update_sql, (kev_run_id,))
        updated = int(self.cursor.rowcount)
        self.log(f"✅ Updated {updated} rows in scorecard with KEV flags.")
        return updated

    def _insert_kev_changes(self, current_run_id: int) -> int:
        """
        Compare the current run to the immediately previous run and insert only
        newly introduced CVEs into kev_changes.

        If there is no previous run, insert nothing.
        """
        assert self.cursor is not None

        previous_run_id = self._get_previous_run_id(current_run_id)

        if previous_run_id is None:
            self.log("ℹ️ No previous run found — skipping kev_changes.")
            return 0

        insert_sql = """
        INSERT INTO kev_changes (kev_run_id, kev_run_data_id)
        SELECT
            cur.kev_run_id,
            cur.kev_run_data_id
        FROM kev_run_data cur
        LEFT JOIN kev_run_data prev
            ON prev.cve_id = cur.cve_id
           AND prev.kev_run_id = %s
        WHERE cur.kev_run_id = %s
          AND prev.kev_run_data_id IS NULL
        """

        self.cursor.execute(insert_sql, (previous_run_id, current_run_id))
        inserted = int(self.cursor.rowcount)
        self.log(f"🆕 Inserted {inserted} rows into kev_changes.")
        return inserted

    def _get_latest_dtkey(self) -> str:
        """
        Get the latest available Tenable dtkey from scorecard.
        """
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

    def _build_daily_top20(self, dtkey: str, kev_run_id: int) -> int:
        """
        Build today's daily_kev_top20 using the current KEV run and latest dtkey.
        """
        assert self.cursor is not None

        self.cursor.execute(
            """
            DELETE FROM daily_kev_top20
            WHERE run_date = CURDATE()
            """
        )

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
                INNER JOIN kev_run_data k
                    ON k.cve_id = s.cve
                   AND k.kev_run_id = %s
                WHERE s.dtkey = %s
                  AND s.kev_flag = 1
                GROUP BY s.pluginid, s.solution
            ) agg
        ) ranked
        WHERE ranked.risk_rank <= 20
        ORDER BY ranked.risk_rank
        """

        self.cursor.execute(insert_sql, (dtkey, kev_run_id, dtkey))
        inserted = int(self.cursor.rowcount)
        self.log(f"📊 Inserted {inserted} rows into daily_kev_top20.")
        return inserted

    def _seed_plugin_status_from_top20(self) -> int:
        """
        Insert today's top-20 plugin IDs into plugin_status if missing.

        Existing plugin_status rows are left unchanged.
        """
        assert self.cursor is not None

        self.cursor.execute(
            """
            INSERT IGNORE INTO plugin_status (
                pluginid
            )
            SELECT DISTINCT
                CAST(t.pluginid AS UNSIGNED) AS pluginid
            FROM daily_kev_top20 t
            WHERE t.run_date = CURDATE()
              AND t.pluginid REGEXP '^[0-9]+$'
            """
        )

        inserted = int(self.cursor.rowcount)
        self.log(f"🧷 Seeded {inserted} new rows into plugin_status.")
        return inserted

    def _fetch_today_top20(self) -> list[dict[str, Any]]:
        """
        Fetch today's top 20 rows for display.
        """
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
        """
        Print compact Teams-style status line.
        """
        status = (
            f"loaded={summary.total_feed_items}; "
            f"changes={summary.changes_rows_inserted}; "
            f"top20={summary.top20_rows_inserted}; "
            f"dtkey={summary.latest_dtkey}"
        )
        print(f"[TO TEAMS==> KEV Status --> {status}]")

    def _print_top20(self) -> None:
        """
        Print today's top 20 in readable table format.
        """
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
        """
        Main execution flow.

        Order of operations:
        1. Connect to DB
        2. Refuse duplicate same-day run
        3. Load KEV feed
        4. Insert kev_run
        5. Insert kev_run_data
        6. Update scorecard with KEV flags for latest dtkey
        7. Insert kev_changes compared to immediately previous run
        8. Build daily_kev_top20
        9. Seed plugin_status from today's daily_kev_top20
        10. Commit and print status
        """
        self._connect_db()

        try:
            self._check_already_loaded()

            data = self._load_feed_json()
            feed_rows = self._normalize_feed(data)

            if not feed_rows:
                raise RuntimeError("KEV feed returned zero vulnerabilities.")

            run_id = self._insert_kev_run()
            self._insert_kev_run_data(run_id, feed_rows)
            self._insert_kev_updates(run_id)
            changes_count = self._insert_kev_changes(run_id)

            latest_dtkey = self._get_latest_dtkey()
            top20_count = self._build_daily_top20(latest_dtkey, run_id)
            self._seed_plugin_status_from_top20()

            assert self.conn is not None
            self.conn.commit()

            summary = KevSummary(
                total_feed_items=len(feed_rows),
                changes_rows_inserted=changes_count,
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
    """
    Build command-line argument parser.
    """
    parser = argparse.ArgumentParser(description="KEV Importer V2")
    parser.add_argument(
        "--noupdate",
        action="store_true",
        help="Skip fetching fresh KEV JSON and use local kev.json",
    )
    return parser


def main() -> None:
    """
    CLI entrypoint.
    """
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
