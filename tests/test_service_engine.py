from __future__ import annotations

import unittest

from serviceEngine import ServiceEngine


class FakeCursor:
    def __init__(
        self,
        fetchone_results: list[dict | None] | None = None,
        fetchall_results: list[dict] | None = None,
    ) -> None:
        self._fetchone_results = fetchone_results or []
        self._fetchone_index = 0
        self._fetchall_results = fetchall_results or []
        self.rowcount = 0
        self.executed: list[tuple[str, tuple | None]] = []

    def execute(self, sql: str, params=None) -> None:
        self.executed.append((sql, params))
        if sql.lstrip().upper().startswith("UPDATE") or sql.lstrip().upper().startswith("INSERT"):
            self.rowcount = 1

    def fetchone(self):
        if self._fetchone_index >= len(self._fetchone_results):
            return None
        result = self._fetchone_results[self._fetchone_index]
        self._fetchone_index += 1
        return result

    def fetchall(self):
        return self._fetchall_results


class ServiceEngineTicketAddTests(unittest.TestCase):
    def test_ticket_add_inserts_when_plugin_status_missing(self) -> None:
        cursor = FakeCursor(fetchone_results=[None])
        engine = ServiceEngine(cursor)

        message = engine.execute("kev", "ticket", "add", "191942", "INC12345")

        self.assertEqual("Linked ticket INC12345 to plugin 191942.", message)
        self.assertEqual(len(cursor.executed), 2)
        self.assertIn("FROM plugin_status", cursor.executed[0][0])
        self.assertIn("INSERT INTO plugin_status", cursor.executed[1][0])

    def test_ticket_update_plugin_changes_status(self) -> None:
        cursor = FakeCursor()
        engine = ServiceEngine(cursor)

        message = engine.execute("kev", "ticket", "update", "plugin", "191942", "closed")

        self.assertEqual("Updated plugin 191942 to closed.", message)
        self.assertEqual(len(cursor.executed), 1)
        self.assertIn("UPDATE plugin_status", cursor.executed[0][0])
        self.assertIn("WHERE pluginid = %s", cursor.executed[0][0])

    def test_ticket_update_id_changes_status(self) -> None:
        cursor = FakeCursor()
        engine = ServiceEngine(cursor)

        message = engine.execute("kev", "ticket", "update", "id", "INC191942", "open")

        self.assertEqual("Updated ticket INC191942 to open.", message)
        self.assertEqual(len(cursor.executed), 1)
        self.assertIn("UPDATE plugin_status", cursor.executed[0][0])
        self.assertIn("WHERE ticketid = %s", cursor.executed[0][0])

    def test_ticket_add_does_not_overwrite_existing_ticket(self) -> None:
        cursor = FakeCursor(fetchone_results=[{"pluginid": 191942, "ticketid": "INC00001"}])
        engine = ServiceEngine(cursor)

        message = engine.execute("kev ticket add 191942 INC99999")

        self.assertEqual("Plugin 191942 already has ticket INC00001. No change made.", message)
        self.assertEqual(len(cursor.executed), 1)
        self.assertIn("FROM plugin_status", cursor.executed[0][0])


class ServiceEngineCloseTests(unittest.TestCase):
    def test_close_sets_status_key_2(self) -> None:
        cursor = FakeCursor(fetchone_results=[])
        engine = ServiceEngine(cursor)

        message = engine.execute("kev", "close", "183969")

        self.assertEqual("Closed plugin 183969.", message)
        self.assertEqual(len(cursor.executed), 1)
        self.assertIn("INSERT INTO plugin_status", cursor.executed[0][0])
        self.assertIn("status_key = 2", cursor.executed[0][0])

    def test_reopen_sets_status_key_1(self) -> None:
        cursor = FakeCursor(fetchone_results=[])
        engine = ServiceEngine(cursor)

        message = engine.execute("kev", "reopen", "183969")

        self.assertEqual("Reopened plugin 183969.", message)
        self.assertEqual(len(cursor.executed), 1)
        self.assertIn("INSERT INTO plugin_status", cursor.executed[0][0])
        self.assertIn("status_key = 1", cursor.executed[0][0])


class ServiceEngineTopStatusTests(unittest.TestCase):
    def test_top_status_returns_chat_summary(self) -> None:
        cursor = FakeCursor(
            fetchall_results=[
                {
                    "risk_rank": 1,
                    "pluginid": "191942",
                    "hosts": 3,
                    "ransomware_flag": 1,
                    "priority_score": 103,
                    "status_key": 1,
                    "status_name": "open",
                    "ticketid": "",
                    "solution": "Apply Security Update 5035885",
                }
            ]
        )
        engine = ServiceEngine(cursor)

        output = engine.execute("kev", "top", "status")

        self.assertIn("KEV Top 20 With Status", output)
        self.assertIn("Fields: rank | plugin | status | ticket | hosts | ransomware | priority", output)
        self.assertIn("1. Plugin 191942 | status: open | ticket: none | 3 host(s) | ransomware: yes | priority: 103", output)
        self.assertIn("Solution: Apply Security Update 5035885", output)


class ServiceEngineHelpTests(unittest.TestCase):
    def test_help_lists_commands(self) -> None:
        cursor = FakeCursor()
        engine = ServiceEngine(cursor)

        output = engine.execute("kev", "help")

        self.assertIn("Supported KEV commands:", output)
        self.assertIn("/kev top", output)
        self.assertIn("/kev ticket update plugin <pluginid> <state>", output)
        self.assertIn("/kev reopen <pluginid>", output)


if __name__ == "__main__":
    unittest.main()
