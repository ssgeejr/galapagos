# Development Notes

## Protected File
- `kev_importer_v2.py` must not be edited.

## System Shape
- This is an OpenClaw agent system.
- The KEV importer is the only non-agent workflow component in active scope.
- Runtime commands are exposed under `/kev`.

## Build-Phase Constraints
- Codex is used only from the CLI as a development tool.
- Do not embed Codex into any software.
- Do not directly link OpenAI to OpenClaw actions.
- Runtime behavior should remain deterministic and class-backed.

## Initial Development Goal
Build the smallest working vertical slice for:

1. `/kev top`
2. `/kev plugin <pluginid>`
3. `/kev status <pluginid>`

After that, add:

4. `/kev ticket add <pluginid> <ticket#>`
5. `/kev ticket update plugin <pluginid> <state>`
6. `/kev ticket update id <ticket#> <state>`
7. `/kev close <pluginid>`
8. `/kev reopen <pluginid>`
9. `/kev top status`
10. `/kev help`

## Preferred Backend Class Layout
- `KevTopService`
- `KevPluginService`
- `KevStatusService`
- `KevTicketService`
- `KevLifecycleService`
- `KevTopStatusService`

## Design Principle
Thin agent handler.
Class-backed logic.
Explicit command parsing.
No guessing.
No drift.
