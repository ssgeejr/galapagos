from __future__ import annotations


class KevHelpService:
    """Read-only service for `/kev help`."""

    _COMMANDS = [
        "/kev help",
        "/kev top",
        "/kev top status",
        "/kev plugin <pluginid>",
        "/kev status <pluginid>",
        "/kev ticket add <pluginid> <ticket#>",
        "/kev ticket update plugin <pluginid> <state>",
        "/kev ticket update id <ticket#> <state>",
        "/kev close <pluginid>",
        "/kev reopen <pluginid>",
    ]

    def run(self) -> str:
        header = "Supported /kev Commands"
        separator = "-" * len(header)
        body = "\n".join(f"{idx}. {cmd}" for idx, cmd in enumerate(self._COMMANDS, start=1))
        return f"{header}\n{separator}\n{body}"
