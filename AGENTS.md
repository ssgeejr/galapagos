# Galapagos instructions

## Purpose
This repo implements KEV Daily Risk Monitoring V2 for daily top-20 KEV risk reporting and AI-generated executive summaries.

This project is an agent system.
The only non-agent workflow component in active scope is `kev_importer_v2.py`, which is the cron-driven daily KEV loader.

---

## Critical Constraints

- Do NOT edit `kev_importer_v2.py`.
- Treat `kev_importer_v2.py` as protected and out of scope for code changes unless explicitly directed otherwise.
- Use Codex only from the CLI as a developer tool.
- Do NOT embed Codex into any software, script, service, or runtime logic.
- Do NOT link or map OpenAI directly to OpenClaw actions.
- Use OpenAI only as a development assistant during the build phase.
- Re-evaluate local LLM and OpenAI runtime usage only after the software is built and validated.

---

## Architecture Rules

- This system is agent-first.
- All newly developed user-facing functionality in this phase is implemented for OpenClaw agent calls.
- Runtime behavior should be driven through OpenClaw command handlers.
- Backend business logic should live in Python classes, not loose procedural scripts.
- Prefer deterministic SQL + Python logic for data retrieval and state changes.
- Keep agent glue thin and business logic reusable.

---

## Coding Rules

- Write Python as classes, not loose procedural scripts.
- Prefer small, focused classes with explicit responsibilities.
- Do not rewrite unrelated working code.
- Make minimal, surgical changes unless asked otherwise.
- Preserve existing workflow behavior unless the request explicitly changes it.
- Prefer adding new files over heavily restructuring existing ones.
- Keep generated SQL and Python ready to paste or save directly.

---

## Project Rules

- This repo lives under OpenClaw.
- V1 remains unchanged.
- V2 is separate.
- Output artifacts go under `/opt/out/galapagos`, not inside the repo.
- Favor warehouse-safe database patterns.
- Do NOT assume uniqueness beyond documented hash logic.
- Do NOT collapse daily snapshot logic and tracking logic into one workflow for convenience.

---

## KEV Workflow Rules

- Use the latest available Tenable snapshot and the current-day KEV snapshot.
- Keep `daily_kev` and `daily_kev_top20` workflows separate and explicit.
- Keep KEV import/loading separate from agent command behavior.
- Treat `top` and change/status tracking operations as separate concerns.

---

## Command Surface Rules

All agent commands use the `/kev` root namespace.

Assume the full invocation pattern is:

`/kev <command> [args...]`

The supported V1 command set is:

- `/kev help`
- `/kev top`
- `/kev top status`
- `/kev plugin <pluginid>`
- `/kev status <pluginid>`
- `/kev ticket add <pluginid> <ticket#>`
- `/kev ticket update plugin <pluginid> <state>`
- `/kev ticket update id <ticket#> <state>`
- `/kev close <pluginid>`
- `/kev reopen <pluginid>`

Rules for command handling:

- Do not remove the `/kev` namespace.
- Keep parsing explicit.
- Do not use fuzzy matching.
- Do not guess whether an identifier is a plugin ID or a ticket number.
- Do not overload commands with hidden side effects.
- Keep write operations explicit and narrow.

---

## Skill File Rule

- Each `/kev` command must be implemented in its own skill file.
- Do NOT combine multiple commands into a single skill file.
- Do NOT create generic or catch-all skill files such as `kev_lookup`.
- Keep each skill file focused on one command only.

---

## Command Intent Reference

### `/kev top`
Show the current top 20 KEV risks.

### `/kev top status`
Show the current top 20 KEV risks with ticket and tracking status overlay.

### `/kev plugin <pluginid>`
Show all affected hosts for the specified plugin.

### `/kev status <pluginid>`
Show the current tracked state for a plugin, including ticket and workflow state.

### `/kev ticket add <pluginid> <ticket#>`
Create a plugin-to-ticket linkage if one does not already exist.

### `/kev ticket update plugin <pluginid> <state>`
Update tracking state by plugin ID.

### `/kev ticket update id <ticket#> <state>`
Update tracking state by ticket number.

### `/kev close <pluginid>`
Mark a plugin as closed.

### `/kev reopen <pluginid>`
Reopen a previously closed plugin.

### `/kev help`
Return the supported command list and usage.

---

## Suggested Implementation Shape

Prefer service classes such as:

- `KevTopService`
- `KevTopStatusService`
- `KevPluginService`
- `KevStatusService`
- `KevTicketService`
- `KevLifecycleService`

Prefer thin command/skill layers that delegate quickly into these classes.

---

## Anti-Patterns

- Do NOT edit `kev_importer_v2.py`.
- Do NOT embed business logic directly in OpenClaw skill files.
- Do NOT introduce unnecessary orchestration layers.
- Do NOT refactor working code without explicit instruction.
- Do NOT expand scope beyond the command requested.
- Do NOT replace explicit command parsing with heuristic parsing.
- Do NOT introduce runtime dependencies on hosted AI services in this phase.

---

## Development Behavior

Before large refactors, show the exact files to be changed.

When adding new functionality:

- prefer new modules over risky rewrites
- keep changes scoped and intentional
- preserve existing import/load workflows
- build the smallest working command first

The priority is:
1. correct behavior
2. simple command handling
3. stable class-based logic
4. future extensibility
