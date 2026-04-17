from __future__ import annotations

import configparser
import sys
from pathlib import Path
from typing import Any

import mysql.connector

from services.kev_plugin_service import KevPluginService
from services.kev_status_service import KevStatusService
from services.kev_ticket_service import KevTicketService
from services.kev_lifecycle_service import KevLifecycleService
from services.kev_top_status_service import KevTopStatusService
from services.kev_top_service import KevTopService
from services.kev_help_service import KevHelpService


class ServiceEngine:
    """Minimal command dispatcher for KEV services."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def execute(self, *args: str) -> str:
        """
        Execute a supported command.

        Supported:
        - "kev top" as first argument, e.g. execute("kev top")
        - "kev top status" as first argument, e.g. execute("kev top status")
        - "kev help" as first argument, e.g. execute("kev help")
        - "kev plugin <pluginid>" as first argument, e.g. execute("kev plugin 191942")
        - "kev status <pluginid>" as first argument, e.g. execute("kev status 191942")
        - "kev ticket add <pluginid> <ticket#>", e.g. execute("kev ticket add 191942 INC123456")
        - "kev ticket update plugin <pluginid> <state>"
        - "kev ticket update id <ticket#> <state>"
        - "kev close <pluginid>", e.g. execute("kev close 183969")
        - "kev reopen <pluginid>", e.g. execute("kev reopen 183969")
        - split form, e.g. execute("kev", "top")
        """
        argv = [arg for arg in args if arg is not None]
        if not argv:
            raise ValueError(
                "No command provided. Use: kev top OR kev plugin <pluginid> "
                "OR kev status <pluginid> OR kev ticket add <pluginid> <ticket#> "
                "OR kev ticket update plugin <pluginid> <state> "
                "OR kev ticket update id <ticket#> <state> "
                "OR kev close <pluginid> OR kev reopen <pluginid>"
            )

        first = argv[0].strip().lower()
        if first == "kev help":
            return KevHelpService().run()

        if first == "kev top status":
            return KevTopStatusService(self._cursor).run()

        if first == "kev top":
            return KevTopService(self._cursor).run()

        if first.startswith("kev plugin "):
            pluginid = argv[0].strip()[len("kev plugin ") :].strip()
            if not pluginid:
                raise ValueError("Usage: kev plugin <pluginid>")
            return KevPluginService(self._cursor).run(pluginid)

        if first.startswith("kev status "):
            pluginid = argv[0].strip()[len("kev status ") :].strip()
            if not pluginid:
                raise ValueError("Usage: kev status <pluginid>")
            return KevStatusService(self._cursor).run(pluginid)

        if first.startswith("kev ticket add "):
            parts = argv[0].strip().split()
            if len(parts) != 5:
                raise ValueError("Usage: kev ticket add <pluginid> <ticket#>")
            return KevTicketService(self._cursor).add_ticket(parts[3], parts[4])

        if first.startswith("kev ticket update plugin "):
            parts = argv[0].strip().split()
            if len(parts) != 6:
                raise ValueError("Usage: kev ticket update plugin <pluginid> <state>")
            return KevTicketService(self._cursor).update_by_plugin(parts[4], parts[5])

        if first.startswith("kev ticket update id "):
            parts = argv[0].strip().split()
            if len(parts) != 6:
                raise ValueError("Usage: kev ticket update id <ticket#> <state>")
            return KevTicketService(self._cursor).update_by_ticket(parts[4], parts[5])

        if first.startswith("kev close "):
            pluginid = argv[0].strip()[len("kev close ") :].strip()
            if not pluginid:
                raise ValueError("Usage: kev close <pluginid>")
            return KevLifecycleService(self._cursor).close(pluginid)

        if first.startswith("kev reopen "):
            pluginid = argv[0].strip()[len("kev reopen ") :].strip()
            if not pluginid:
                raise ValueError("Usage: kev reopen <pluginid>")
            return KevLifecycleService(self._cursor).reopen(pluginid)

        if len(argv) >= 2 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "top":
            if len(argv) >= 3 and argv[2].strip().lower() == "status":
                return KevTopStatusService(self._cursor).run()
            return KevTopService(self._cursor).run()

        if len(argv) >= 2 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "help":
            return KevHelpService().run()

        if len(argv) >= 3 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "plugin":
            pluginid = argv[2].strip()
            if not pluginid:
                raise ValueError("Usage: kev plugin <pluginid>")
            return KevPluginService(self._cursor).run(pluginid)

        if len(argv) >= 3 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "status":
            pluginid = argv[2].strip()
            if not pluginid:
                raise ValueError("Usage: kev status <pluginid>")
            return KevStatusService(self._cursor).run(pluginid)

        if len(argv) >= 5 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "ticket" and argv[2].strip().lower() == "add":
            pluginid = argv[3].strip()
            ticketid = argv[4].strip()
            if not pluginid or not ticketid:
                raise ValueError("Usage: kev ticket add <pluginid> <ticket#>")
            return KevTicketService(self._cursor).add_ticket(pluginid, ticketid)

        if (
            len(argv) >= 6
            and argv[0].strip().lower() == "kev"
            and argv[1].strip().lower() == "ticket"
            and argv[2].strip().lower() == "update"
            and argv[3].strip().lower() == "plugin"
        ):
            pluginid = argv[4].strip()
            state = argv[5].strip()
            if not pluginid or not state:
                raise ValueError("Usage: kev ticket update plugin <pluginid> <state>")
            return KevTicketService(self._cursor).update_by_plugin(pluginid, state)

        if (
            len(argv) >= 6
            and argv[0].strip().lower() == "kev"
            and argv[1].strip().lower() == "ticket"
            and argv[2].strip().lower() == "update"
            and argv[3].strip().lower() == "id"
        ):
            ticketid = argv[4].strip()
            state = argv[5].strip()
            if not ticketid or not state:
                raise ValueError("Usage: kev ticket update id <ticket#> <state>")
            return KevTicketService(self._cursor).update_by_ticket(ticketid, state)

        if len(argv) >= 3 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "close":
            pluginid = argv[2].strip()
            if not pluginid:
                raise ValueError("Usage: kev close <pluginid>")
            return KevLifecycleService(self._cursor).close(pluginid)

        if len(argv) >= 3 and argv[0].strip().lower() == "kev" and argv[1].strip().lower() == "reopen":
            pluginid = argv[2].strip()
            if not pluginid:
                raise ValueError("Usage: kev reopen <pluginid>")
            return KevLifecycleService(self._cursor).reopen(pluginid)

        raise ValueError(
            "Unsupported command. Implemented: 'kev help', 'kev top', 'kev top status', 'kev plugin <pluginid>', "
            "'kev status <pluginid>', 'kev ticket add <pluginid> <ticket#>', "
            "'kev ticket update plugin <pluginid> <state>', "
            "'kev ticket update id <ticket#> <state>', "
            "'kev close <pluginid>', 'kev reopen <pluginid>'."
        )


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
            print(
                "Usage: python serviceEngine.py kev top|plugin|status|close <pluginid> "
                "OR kev help "
                "OR kev ticket add <pluginid> <ticket#> "
                "OR kev ticket update plugin <pluginid> <state> "
                "OR kev ticket update id <ticket#> <state> "
                "OR kev reopen <pluginid>",
                file=sys.stderr,
            )
            return 2

        db_config = cls.load_db_config()
        conn = mysql.connector.connect(**db_config)
        try:
            cursor = conn.cursor(dictionary=True)
            try:
                output = ServiceEngine(cursor).execute(*argv)
                conn.commit()
                print(output)
                #return output
            except Exception:
                conn.rollback()
                raise
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
