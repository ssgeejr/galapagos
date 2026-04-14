from __future__ import annotations

import configparser
import sys
from pathlib import Path
from typing import Any

import mysql.connector

from services.kev_plugin_service import KevPluginService
from services.kev_top_service import KevTopService


class ServiceEngine:
    """Minimal command dispatcher for KEV services."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def execute(self, *args: str) -> str:
        """
        Execute a supported command.

        Supported:
        - "kev top" as first argument, e.g. execute("kev top")
        - "kev plugin <pluginid>" as first argument, e.g. execute("kev plugin 191942")
        - split form, e.g. execute("kev", "top")
        """
        argv = [arg for arg in args if arg is not None]
        if not argv:
            raise ValueError("No command provided. Use: kev top OR kev plugin <pluginid>")

        first = argv[0].strip().lower()
        if first == "kev top":
            return KevTopService(self._cursor).run()

        if first.startswith("kev plugin "):
            pluginid = argv[0].strip()[len("kev plugin ") :].strip()
            if not pluginid:
                raise ValueError("Usage: kev plugin <pluginid>")
            return KevPluginService(self._cursor).run(pluginid)

        if len(argv) >= 2 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "top":
            return KevTopService(self._cursor).run()

        if len(argv) >= 3 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "plugin":
            pluginid = argv[2].strip()
            if not pluginid:
                raise ValueError("Usage: kev plugin <pluginid>")
            return KevPluginService(self._cursor).run(pluginid)

        raise ValueError("Unsupported command. Implemented: 'kev top', 'kev plugin <pluginid>'.")


class ServiceEngineRunner:
    """CLI runner for ServiceEngine."""

    CONFIG_PATH = Path.home() / ".neurosentinel" / "db.conf"

    @classmethod
    def load_db_config(cls) -> dict[str, Any]:
        config = configparser.RawConfigParser()
        if not cls.CONFIG_PATH.exists():
            raise FileNotFoundError(
                f"Database config not found: {cls.CONFIG_PATH}\n"
                "Expected format:\n"
                "[mysql]\n"
                "host = localhost\n"
                "port = 3306\n"
                "user = your_username\n"
                "password = your_password\n"
                "database = your_database\n"
            )

        config.read(cls.CONFIG_PATH)
        if "mysql" not in config:
            raise ValueError(f"[mysql] section missing in {cls.CONFIG_PATH}")

        mysql_cfg = config["mysql"]
        return {
            "host": mysql_cfg.get("host", "localhost"),
            "port": mysql_cfg.getint("port", 3306),
            "user": mysql_cfg.get("user"),
            "password": mysql_cfg.get("password"),
            "database": mysql_cfg.get("database"),
        }

    @classmethod
    def run(cls, argv: list[str]) -> int:
        if not argv:
            print("Usage: python serviceEngine.py kev top|plugin <pluginid>", file=sys.stderr)
            return 2

        db_config = cls.load_db_config()
        conn = mysql.connector.connect(**db_config)
        try:
            cursor = conn.cursor(dictionary=True)
            try:
                output = ServiceEngine(cursor).execute(*argv)
                print(output)
            finally:
                cursor.close()
        finally:
            conn.close()

        return 0


def main() -> int:
    try:
        return ServiceEngineRunner.run(sys.argv[1:])
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
