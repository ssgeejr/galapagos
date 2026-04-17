# OpenClaw Skill Bundle (KEV V2)

This folder packages the existing KEV V2 command implementation for OpenClaw.

## Included Skills

- `openclaw/skills/kev-help`
- `openclaw/skills/kev-top`
- `openclaw/skills/kev-top-status`
- `openclaw/skills/kev-plugin`
- `openclaw/skills/kev-status`
- `openclaw/skills/kev-ticket-add`
- `openclaw/skills/kev-ticket-update-plugin`
- `openclaw/skills/kev-ticket-update-id`
- `openclaw/skills/kev-close`
- `openclaw/skills/kev-reopen`

Each skill is command-specific and delegates to the existing backend runtime in `serviceEngine.py`.

## Runtime Contract

All skills use the `/kev` namespace and explicit command parsing:

`/kev <command> [args...]`

Supported commands are unchanged from V1 command surface.

## Install Into OpenClaw Agent

Example for agent `kev-analyst`:

```bash
mkdir -p ~/.openclaw/agents/kev-analyst/skills
cp -R /opt/apps/galapagos/openclaw/skills/* ~/.openclaw/agents/kev-analyst/skills/
```

## Validate

```bash
python -m unittest tests/test_service_engine.py
python serviceEngine.py kev help
python serviceEngine.py kev top
```

## Constraints

- `kev_importer_v2.py` remains protected and unchanged.
- Business logic remains in service classes under `services/`.
- Skill layer remains thin and command-scoped.
