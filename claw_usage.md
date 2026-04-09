# OpenClaw Teams Integration: Command Whitelisting Architecture
**Date:** April 9, 2026  
**Context:** NeuroSentinel KEV-Analyst agent with restricted Teams access  
**Status:** Architecture Phase (pre-implementation)

---

## Project Context

### Goal
Enable NeuroSentinel to be accessed via Teams by IT teams, with **unconditional restrictions** to only approved commands. No full OpenClaw power exposed to Teams users.

### Background
- Steven (CISO, WMMC) is building NeuroSentinel security platform
- Two systems: **local NeuroSentinel** (AWS instance) and **OpenClaw** (AI server, GRAVITYDRIVE)
- These are NOT related and do NOT run on the same computer
- Final deliverable: Teams integration for IT teams to query KEV top 20 and ticket management

### Development Plan (from previous session)
```
[x] implemented: pull daily KEV, insert into database, insert changes into database, update scorecard
[ ] Create new skills for kev-analyst agent
    [ ] Request top 20 patch list (under development)
    [ ] Request status (conceptual)
    [ ] Assign ticket# to CEV (conceptual)
    [ ] Update ticket# to CEV (conceptual)
```

**Active OpenClaw Agents:**
- main (Main Assistant)
- architect (Architect - SaltedEarth Design Notes)
- biscuits (Biscuits)
- kev-analyst (KEV Analyst) ← TARGET AGENT FOR TEAMS
- peoples (Peoples - Threat Actor)

---

## OpenClaw Version & Environment

**OpenClaw Version:** 2026.2.27

### GRAVITYDRIVE Environment
- **System:** GMKtec EVO-X2
- **OS:** Windows 11 Pro
- **RAM:** 128GB DDR5 (96GB GPU VRAM via UMA)
- **GPU:** AMD Radeon 8060S (integrated, Vulkan)
- **llama.cpp Instances:**
  - Qwen3-Coder-Next Q6_K 79B at `http://172.25.112.1:8080/v1` (port 8080, 128k context)
  - WhiteRabbitNeo V3 7B at `http://172.25.112.1:8081/v1` (port 8081, 64k context)

### OpenClaw Key Paths
- **Config:** `~/.openclaw/openclaw.json`
- **Agents:** `~/.openclaw/agents/`
- **KEV-Analyst Agent:** `~/.openclaw/agents/kev-analyst/`
- **Skills:** `.openclaw/agents/{agent-name}/` (SKILL.md files)
- **Sessions:** `~/.openclaw/agents/kev-analyst/sessions/`

---

## OpenClaw CLI Commands Reference

### Relevant Commands for Whitelisting/Security

```bash
# Gateway & Security
openclaw gateway                    # Control Gateway
openclaw security audit             # Security audit with optional --deep, --fix, --json
openclaw security audit --json      # Machine-readable security report

# Webhooks & Automation
openclaw webhooks --help            # Webhook helpers
openclaw webhooks gmail setup       # Gmail integration
openclaw webhooks gmail run         # Run Gmail Pub/Sub

# Agent Management
openclaw agents                     # Manage isolated agents
openclaw agent --to TARGET --message "command"  # Invoke agent
openclaw agent --to TARGET --message "command" --deliver  # With delivery

# Skills
openclaw skills                     # Skills management
openclaw skills list                # List available skills

# Sessions
openclaw sessions                   # List stored conversation sessions
openclaw session reset              # Clear session state
```

### Full CLI Reference (from help output)
- setup, onboard, configure, config, doctor, dashboard
- reset, uninstall, message, memory, agent, agents, acp
- gateway, daemon, logs, system, models, approvals, nodes, device
- node, sandbox, tui, cron, dns, docs, hooks, pairing
- security, skills, plugins, channels, directory, update, completion, status, health

---

## OpenClaw Webhook Architecture

### Key Security Features (from docs.openclaw.ai/cli/webhooks)

**Webhook Ingress Controls:**
1. `hooks.token` — Shared secret for webhook authentication
   - ⚠️ **WARNING:** Don't reuse Gateway token (security audit warns about this)

2. `hooks.defaultSessionKey` — Default session for webhook requests
   - ⚠️ **WARNING:** Must be set (security audit warns if unset)

3. `hooks.allowedAgentIds` — Agent whitelist for webhooks
   - ⚠️ **WARNING:** Security audit warns if unrestricted
   - **USE THIS:** Restrict webhooks to ONLY kev-analyst agent

4. `hooks.allowedSessionKeyPrefixes` — Session key prefix whitelist
   - Controls which sessions webhooks can override

### Webhook Configuration Pattern
```json
{
  "hooks": {
    "token": "unique-webhook-token-not-gateway-token",
    "defaultSessionKey": "teams-webhook-session",
    "allowedAgentIds": ["kev-analyst"],
    "allowedSessionKeyPrefixes": ["teams-"],
    "requestSessionKeyOverride": false
  }
}
```

---

## OpenClaw Security Architecture

### Security Audit Coverage (from docs.openclaw.ai/cli/security)

The `openclaw security audit` command checks for:

1. **Multi-user/shared inbox hardening**
   - Recommends `session.dmScope="per-channel-peer"` for shared inboxes
   - Warns on `multi_user_heuristic` when config suggests shared access

2. **Webhook ingress hardening**
   - ✅ Warns if `hooks.token` reuses Gateway token
   - ✅ Warns if `hooks.defaultSessionKey` is unset
   - ✅ Warns if `hooks.allowedAgentIds` is unrestricted
   - ✅ Warns if request `sessionKey` overrides enabled without `hooks.allowedSessionKeyPrefixes`

3. **Sandbox & tool isolation**
   - Warns when small models (≤300B) used without sandboxing + web/browser tools
   - Checks sandbox Docker config vs sandbox mode enabled
   - Flags dangerous node commands in `gateway.nodes.denyCommands`
   - Warns on open groups exposing runtime/filesystem tools without sandbox/workspace guards

4. **Dangerous parameters**
   - Flags `gateway.allowRealIpFallback=true` (header-spoofing risk)
   - Flags `discovery.mdns.mode="full"` (mDNS metadata leakage)
   - Checks for unpinned npm plugins, missing integrity metadata

5. **Channel allowlists**
   - Warns when allowlists use mutable names/emails/tags instead of stable IDs

### Security Audit Output Formats
```bash
# Human-readable audit
openclaw security audit

# Deep audit (probes credentials)
openclaw security audit --deep

# With password/token override
openclaw security audit --deep --password <password>
openclaw security audit --deep --token <token>

# Auto-fix safe issues
openclaw security audit --fix

# Machine-readable (JSON)
openclaw security audit --json
openclaw security audit --deep --json

# CI/Policy checks
openclaw security audit --json | jq '.summary'
openclaw security audit --json | jq '.findings[] | select(.severity=="critical") | .checkId'

# Combined fix + report (JSON)
openclaw security audit --fix --json | jq '{fix: .fix.ok, summary: .report.summary}'
```

### What `--fix` Changes
- Converts `groupPolicy="open"` to `groupPolicy="allowlist"`
- Sets `logging.redactSensitive` from `"off"` to `"tools"`
- Tightens file permissions on state/config/credentials/sessions

### What `--fix` Does NOT Change
- ❌ Rotate tokens/passwords/API keys
- ❌ Disable tools (gateway, cron, exec, etc.)
- ❌ Change gateway bind/auth/network exposure
- ❌ Remove or rewrite plugins/skills

---

## KEV-Analyst Agent Current State

### Existing Skills

**kev-lookup Skill** (from SKILL.md)
```markdown
# kev-lookup Skill

Purpose:
- Download latest KEV JSON from CISA
- Compare with previous version
- Report new/removed/updated CVEs
- Save summary markdown file

Working Directory: /opt/apps/kevctem

Trigger Phrases:
- "lookup any new kevs"
- "check kev"
- "new kev updates"
- "run kev diff"
- "cisa kev"
- "kev lookup"
- "show me new known exploited vulnerabilities"

Required Tools:
- exec
- read
- write

Output:
- Console summary with CVE table
- Markdown summary saved to `kev-summary-MMDDYYYY.md`

Implementation:
- Script: `/opt/apps/kevctem/scripts/kev_lookup.py`
- JSON files: `/opt/apps/kevctem/kev-MMDDYYYY.json`
- Summaries: `/opt/apps/kevctem/kev-summary-MMDDYYYY.md`
```

### Known Issues with Current Implementation
- `reset-session` skill requires `/` prefix while `check kev` does not (consistency issue)
- KEV-Analyst agent had hardcoded "check kev" trigger causing looping; resolved by clearing `.jsonl` conversation history files (not just `sessions.json`)

---

## NeuroSentinel Skills Under Development

### Phase III Skills (Architecture Locked)

#### 1. Request Top 20 Patch List
**Status:** Under Development  
**Purpose:** Ranked list of top 20 KEV-flagged vulnerabilities by priority score

**Locked Specifications:**
- Q1.2: LOCKED — Truncate solution to 64 characters
- Q1.3: LOCKED — Show fields: pluginid, hosts, ransomware_flag, priority_score, solution

**Open Questions:**
- Q1.1: Output format for Teams? (table, JSON, HTML card, plain text?)
- Q1.4: Output filters? (ransomware=1 only, >5 hosts minimum?)
- Q1.5: Dynamic refresh or snapshot at call time?

**Database Query (LOCKED):**
```sql
SELECT
  solution,
  pluginid,
  COUNT(DISTINCT host) AS hosts,
  MAX(kev_ransomware_flag) AS ransomware,
  COUNT(DISTINCT host) + (CASE WHEN MAX(kev_ransomware_flag) = 1 THEN 100 ELSE 0 END) AS priority_score
FROM scorecard
WHERE dtkey = (
  SELECT dtkey
  FROM scorecard
  WHERE kev_flag = 1
  ORDER BY
    SUBSTR(dtkey, 3, 2) DESC,
    SUBSTR(dtkey, 1, 2) DESC,
    SUBSTR(dtkey, 5, 1) DESC
  LIMIT 1
)
AND kev_flag = 1
GROUP BY solution, pluginid
ORDER BY priority_score DESC, hosts DESC
LIMIT 20
```

**Python Function (DRAFT):**
```python
def _fetch_kev_top20(self) -> list[dict[str, Any]]:
    """
    Fetch the latest KEV top 20 ranked by priority score.
    
    Autonomously selects the latest dtkey where kev_flag = 1,
    then ranks by priority_score (host count + ransomware bonus).
    
    Solution field is truncated to 64 characters for display.
    
    Returns a list of dicts with: solution, pluginid, hosts, ransomware, priority_score
    """
    assert self.cursor is not None

    self.cursor.execute(
        """
        SELECT
          solution,
          pluginid,
          COUNT(DISTINCT host) AS hosts,
          MAX(kev_ransomware_flag) AS ransomware,
          COUNT(DISTINCT host) + (CASE WHEN MAX(kev_ransomware_flag) = 1 THEN 100 ELSE 0 END) AS priority_score
        FROM scorecard
        WHERE dtkey = (
          SELECT dtkey
          FROM scorecard
          WHERE kev_flag = 1
          ORDER BY
            SUBSTR(dtkey, 3, 2) DESC,
            SUBSTR(dtkey, 1, 2) DESC,
            SUBSTR(dtkey, 5, 1) DESC
          LIMIT 1
        )
        AND kev_flag = 1
        GROUP BY solution, pluginid
        ORDER BY priority_score DESC, hosts DESC
        LIMIT 20
        """
    )

    rows = list(self.cursor.fetchall())
    
    # Truncate solution to 64 characters
    for row in rows:
        if row.get("solution"):
            row["solution"] = row["solution"][:64]
    
    return rows
```

#### 2. Request Status
**Status:** Conceptual  
**Purpose:** Query system state and KEV import status

**Open Questions:**
- Q2.1: [IT] Latest KEV Import Run — Show run_date, total_loaded, changes_count, top20_count, latest_dtkey?
- Q2.2: [IT] Individual CVEs/PluginIDs — What info? (date_added, due_date, hosts_affected, ransomware_flag, ticket_status?)
- Q2.3: [Admin] Overall System Health — Metrics? (last_run_time, next_scheduled_run, failures/warnings?)

#### 3. Get Hosts by PluginID
**Status:** Conceptual  
**Purpose:** Return list of affected hosts for a given plugin vulnerability

**Open Questions:**
- Q3.1: Return data — hostnames, IPs, count only, host+status?
- Q3.2: KEV filter — KEV-flagged only or all hosts with that pluginid?
- Q3.3: Output format — Teams display or raw data?

#### 4-8. Ticket Management Skills
**Status:** Conceptual (requires new database table)

**Skills:**
- add ticket # (create/link ticket to CVE)
- open tickets (list all open tickets)
- close ticket # (mark ticket as closed)
- status ticket # (check ticket status)
- search ticket # (find ticket by number)
- search cve # (find tickets linked to CVE)
- update ticket # (modify ticket details)
- assign ticket # (assign to team member)

**Open Questions:**
- Q4.1: Table schema — fields? (ticket_id, cve_id, pluginid, status, assigned_to, created_date, closed_date, jira_id, notes, ...)
- Q4.2: Ticket lifecycle — statuses? (open, assigned, in_progress, closed, rejected, ...)
- Q4.3: Auto-assignment — AI auto-assign or manual?
- Q4.4: CVE mapping — 1:1 or multiple tickets per CVE?
- Q4.5: Jira integration — Link to Jira/ServiceNow? (YES)
- Q4.6: 'add ticket #' — Create new or link existing?
- Q4.7: 'search ticket #' — By ticket number or CVE/pluginid?
- Q4.8: 'search cve #' — CVE string format (CVE-2024-1234)?

---

## Command Whitelisting Architecture

### Threat Model
Protection against:
- Accidental misuse (user typos wrong command)
- Intentional abuse (user tries to escalate privileges)
- Compromised Teams account (attacker gains Teams access)

### Architecture Options

**OPTION A: Whitelist at OpenClaw Agent Level**
- kev-analyst agent config explicitly lists allowed skills/commands
- OpenClaw rejects anything not in the list before execution
- **Pro:** Centralized, auditable, lives in agent config
- **Con:** Depends on OpenClaw's ability to enforce

**OPTION B: Whitelist at Teams Webhook**
- Webhook receives Teams message, validates command against whitelist
- Only passes approved commands to OpenClaw
- **Pro:** Defense-in-depth, Teams never touches unapproved OpenClaw code
- **Con:** Extra layer to maintain, command parsing logic duplicated

**OPTION C: Hybrid (RECOMMENDED)**
- Teams webhook validates (first line of defense)
- OpenClaw agent config also validates (second line of defense)
- Belt and suspenders: one fails, the other catches it

**OPTION D: OpenClaw Agent Isolation**
- Run kev-analyst in restricted execution context
- No filesystem access, no sub-agent spawning, only DB queries
- Whitelist enforced by OpenClaw gateway/runtime, not just config

### Recommended Implementation: OPTION A + C (Hybrid)

#### Layer 1: Teams Webhook Validation
```python
# Pseudocode for Teams webhook handler
ALLOWED_COMMANDS = {
    "top 20": "fetch_kev_top20",
    "status": "fetch_kev_status",
    "hosts pluginid": "get_hosts_by_pluginid",
    "add ticket": "add_ticket",
    "search ticket": "search_ticket",
    "search cve": "search_cve",
    # ... more commands
}

def validate_teams_message(message: str) -> bool:
    """Check if message starts with allowed command."""
    for cmd in ALLOWED_COMMANDS.keys():
        if message.lower().startswith(cmd):
            return True
    return False

def teams_webhook_handler(request):
    message = request.json.get("text", "").strip()
    
    if not validate_teams_message(message):
        return {"error": "Command not allowed"}, 403
    
    # Pass to kev-analyst agent via OpenClaw webhook
    return invoke_openclaw_webhook(message)
```

#### Layer 2: OpenClaw Agent Configuration
```json
{
  "agents": {
    "kev-analyst": {
      "workspace": "/opt/apps/openclaw/agents/kev-analyst",
      "tools": {
        "profile": "minimal",
        "allowedTools": ["database", "read"]
      },
      "skills": {
        "allowedSkills": [
          "fetch_kev_top20",
          "fetch_kev_status",
          "get_hosts_by_pluginid",
          "add_ticket",
          "search_ticket",
          "search_cve"
        ]
      },
      "sandbox": {
        "enabled": true,
        "filesystem": {
          "allowedPaths": ["/opt/apps/openclaw/agents/kev-analyst"]
        }
      }
    }
  },
  "hooks": {
    "token": "unique-webhook-token-not-gateway-token",
    "defaultSessionKey": "teams-webhook-session",
    "allowedAgentIds": ["kev-analyst"],
    "allowedSessionKeyPrefixes": ["teams-"],
    "requestSessionKeyOverride": false
  }
}
```

#### Layer 3: Skill Definition Restrictions
```markdown
# kev-top20 Skill (example)

## Trigger Phrases
- "top 20"
- "top twenty"
- "patch list"
- "show me top 20"

## Purpose
Return top 20 KEV-flagged vulnerabilities ranked by priority score

## Required Tools
- database (read-only)

## Restricted
- No exec
- No filesystem write
- No network access
- No sub-agent invocation
```

---

## Security Validation Checklist

Before Teams launch, run:

```bash
# Comprehensive security audit
openclaw security audit --deep --json

# Verify webhook configuration
openclaw config get hooks

# Verify agent restrictions
openclaw agents list --detailed
openclaw agents show kev-analyst

# Verify sandbox is enabled
openclaw config get agents.kev-analyst.sandbox

# Check for dangerous parameters
openclaw security audit --json | jq '.findings[] | select(.severity=="critical")'

# Validate no filesystem access
openclaw security audit --json | jq '.findings[] | select(.checkId=="filesystem")'

# Verify token separation
openclaw security audit --json | jq '.findings[] | select(.checkId=="hooks_token_reuse")'
```

---

## Implementation Roadmap

### Phase 1: Architecture & Config
- [ ] Lock answers to all Q1-Q4 questions
- [ ] Finalize allowed command list
- [ ] Design Teams webhook handler
- [ ] Configure OpenClaw `hooks.*` settings
- [ ] Design agent skill SKILL.md files

### Phase 2: Database & Backend
- [ ] Implement `_fetch_kev_top20()` Python function
- [ ] Implement `_fetch_kev_status()` function
- [ ] Implement `get_hosts_by_pluginid()` function
- [ ] Create ticket tracking table schema
- [ ] Implement ticket management functions

### Phase 3: OpenClaw Skills
- [ ] Create `fetch_kev_top20` skill (SKILL.md + implementation)
- [ ] Create `fetch_kev_status` skill
- [ ] Create `get_hosts_by_pluginid` skill
- [ ] Create ticket management skills
- [ ] Test skill triggers and outputs

### Phase 4: Teams Integration
- [ ] Build Teams webhook handler
- [ ] Implement command validation
- [ ] Format output for Teams display (tables, cards, etc.)
- [ ] Test end-to-end message flow

### Phase 5: Security Hardening
- [ ] Run `openclaw security audit --deep`
- [ ] Address all findings
- [ ] Apply `openclaw security audit --fix`
- [ ] Implement sandbox restrictions
- [ ] Validate no unauthorized tool access

### Phase 6: Testing & Launch
- [ ] Unit tests for Python functions
- [ ] Integration tests for skill invocation
- [ ] Load testing (Teams message throughput)
- [ ] Security penetration testing
- [ ] Documentation for IT team
- [ ] Launch to Teams

---

## Key Decision Points

1. **Command Whitelist Scope**
   - Which commands from Phase III are MVP?
   - How many do we launch with vs iterate?

2. **Output Format for Teams**
   - Teams messages, adaptive cards, threads, or rich formatting?
   - How do we display top 20 table in Teams best way?

3. **Authentication & Authorization**
   - User identity validation from Teams?
   - Role-based access (IT vs Admin)?

4. **Error Handling**
   - What happens if a query fails?
   - Do we log unauthorized attempts?

5. **Monitoring & Alerting**
   - How do we track Teams webhook usage?
   - Do we alert on suspicious activity?

---

## Files & References

### NeuroSentinel Files (Local)
- **Updated:** `/mnt/user-data/outputs/kev_importer_v2.py` (with `_insert_kev_updates` function)
- **Blueprint:** `_fetch_kev_top20()` function (draft in this document)

### OpenClaw Documentation
- **Webhooks:** https://docs.openclaw.ai/cli/webhooks
- **Security:** https://docs.openclaw.ai/cli/security
- **Automation:** https://docs.openclaw.ai/automation/webhook

### Architecture Documents (this session)
- **phaseiii.pdf** — Phase III skills architecture with locked questions

---

## Notes for Future Sessions

### What We Know
- OpenClaw 2026.2.27 supports webhook command validation via `hooks.allowedAgentIds`
- KEV-Analyst agent exists and is ready for skill expansion
- Database queries for top 20 are locked and validated
- Hybrid whitelisting (webhook + agent config) is recommended

### What We DON'T Know Yet
- Final output format for Teams (Q1.1)
- All answers to Q1.4-Q1.5, Q2.1-Q2.3, Q3.1-Q3.3, Q4.1-Q4.8
- Exact MVP command list
- User authentication strategy
- Teams card/formatting design

### Action Items for Next Session
1. Answer remaining Phase III questions (lock them)
2. Finalize allowed command whitelist
3. Design Teams webhook handler (language/framework?)
4. Begin Phase 2 implementation (database functions)

---

## Glossary

- **GRAVITYDRIVE:** Steven's air-gapped development environment (Windows 11, 128GB RAM, local llama.cpp)
- **NeuroSentinel:** Security platform with KEV monitoring, vulnerability tracking, ticket management
- **OpenClaw:** Agent orchestration framework with webhooks, skills, multi-agent routing
- **KEV:** Known Exploited Vulnerabilities (CISA feed)
- **kev-analyst:** OpenClaw agent dedicated to KEV queries and ticket management
- **kev_flag:** Database flag (1=0) marking scorecard records as KEV-related
- **dtkey:** Tenable scan identifier (format: MMYY[A,B] — e.g., 0426A = April 2026, first load)
- **priority_score:** Calculated rank = host_count + (ransomware_flag ? 100 : 0)
- **Whitelist:** Explicit list of allowed commands (anything not listed is rejected)
- **Webhook:** HTTP POST from Teams to OpenClaw Gateway to invoke agent
- **Sandbox:** Restricted execution context (no filesystem write, no network, minimal tools)
- **SKILL.md:** Agent skill definition (triggers, purpose, required tools, implementation path)
- **Hook:** OpenClaw term for webhook configuration and handling

---

**Document Version:** 1.0  
**Last Updated:** April 9, 2026  
**Next Review:** Next architecture session
