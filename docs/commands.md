# /kev Commands

All commands are invoked through the `/kev` namespace.

## Supported Commands

### `/kev help`
Show available commands and usage.

### `/kev top`
Show the current KEV top 20.

### `/kev top status`
Show the current KEV top 20 with ticket and workflow status.

### `/kev plugin <pluginid>`
Show all affected hosts for a given plugin.

### `/kev status <pluginid>`
Show the tracked state for a plugin, including ticket linkage and current workflow state.

### `/kev ticket add <pluginid> <ticket#>`
Add a ticket mapping for a plugin if one does not already exist.

### `/kev ticket update plugin <pluginid> <state>`
Update ticket/workflow state by plugin ID.

### `/kev ticket update id <ticket#> <state>`
Update ticket/workflow state by ticket number.

### `/kev close <pluginid>`
Mark a plugin as closed.

### `/kev reopen <pluginid>`
Reopen a previously closed plugin.

## Notes

- Parsing must remain explicit.
- Do not infer identifier type.
- Do not add hidden side effects to read commands.
- The `/kev` prefix is mandatory in runtime usage even if omitted in design discussion.
