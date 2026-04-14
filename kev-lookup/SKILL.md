# /kev top Skill

## Purpose
Handle only `/kev top` and return the current KEV Top 20 as a formatted table.

## Command
- `/kev top`

## Parsing Rules
- Require exact `/kev top`.
- Do not infer, fuzzy-match, or route other `/kev` commands here.

## Runtime Behavior
- Keep this layer thin.
- Delegate query and table rendering to `services/kev_top_service.py` (`KevTopService`).

## Data Query
Use the approved Top 20 query pattern already defined in the project.

## Output
Return a clean fixed-width table with:
- rank
- pluginid
- hosts
- ransomware flag
- priority score
- solution (truncated for display)
