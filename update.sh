#!/usr/bin/env bash
set -euo pipefail

OPENCLAW_HOME="${HOME}/.openclaw"
TIMESTAMP="$(date +%F-%H%M%S)"
BACKUP_DIR="${OPENCLAW_HOME}/archive-old-kev/${TIMESTAMP}"
PRIMARY_KEV_SKILLS_DIR="${OPENCLAW_HOME}/agents/kev-analyst/skills"
SOURCE_KEV_SKILLS_DIR="/opt/apps/galapagos/openclaw/skills"

log() {
  printf '[update.sh] %s\n' "$1"
}

ensure_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    log "Missing file: $f (skipping)"
    return 1
  fi
  return 0
}

backup_file() {
  local src="$1"
  local dst_dir="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$dst_dir"
    cp "$src" "$dst_dir/"
    log "Backed up: $src"
  fi
}

archive_dir_with_unique_name() {
  local src="$1"
  local dst_root="$2"
  local tag="$3"

  if [[ ! -d "$src" ]]; then
    return 0
  fi

  mkdir -p "$dst_root"
  local dst="${dst_root}/${tag}"

  if [[ -e "$dst" ]]; then
    local i=1
    while [[ -e "${dst}-${i}" ]]; do
      i=$((i + 1))
    done
    dst="${dst}-${i}"
  fi

  mv "$src" "$dst"
  log "Archived folder: $src -> $dst"
}

log "Starting OpenClaw legacy KEV cleanup"
mkdir -p "$BACKUP_DIR"

# 0) Normalize KEV skill location (keep only one canonical copy)
mkdir -p "$PRIMARY_KEV_SKILLS_DIR"
log "Canonical KEV skills location: $PRIMARY_KEV_SKILLS_DIR"

if [[ -d "$SOURCE_KEV_SKILLS_DIR" ]]; then
  cp -R "${SOURCE_KEV_SKILLS_DIR}/"* "$PRIMARY_KEV_SKILLS_DIR/"
  log "Synced KEV skills into canonical location from: $SOURCE_KEV_SKILLS_DIR"
else
  log "Missing source KEV skills dir: $SOURCE_KEV_SKILLS_DIR"
  exit 1
fi

mkdir -p "${BACKUP_DIR}/duplicate-kev-skills"
for skills_dir in "${OPENCLAW_HOME}"/agents/*/skills; do
  [[ -d "$skills_dir" ]] || continue
  [[ "$skills_dir" == "$PRIMARY_KEV_SKILLS_DIR" ]] && continue

  shopt -s nullglob
  kev_dirs=("${skills_dir}"/kev-*)
  shopt -u nullglob

  if (( ${#kev_dirs[@]} > 0 )); then
    agent_name="$(basename "$(dirname "$skills_dir")")"
    mkdir -p "${BACKUP_DIR}/duplicate-kev-skills/${agent_name}"
    for kd in "${kev_dirs[@]}"; do
      mv "$kd" "${BACKUP_DIR}/duplicate-kev-skills/${agent_name}/"
      log "Archived duplicate KEV skill: ${kd}"
    done
  fi
done

# 1) Backup key files
backup_file "${OPENCLAW_HOME}/workspace/MEMORY.md" "$BACKUP_DIR"
backup_file "${OPENCLAW_HOME}/workspace/memory/2026-03-24.md" "$BACKUP_DIR"
backup_file "${OPENCLAW_HOME}/agents/main/sessions/sessions.json" "$BACKUP_DIR"
backup_file "${OPENCLAW_HOME}/agents/biscuits/sessions/sessions.json" "$BACKUP_DIR"
backup_file "${OPENCLAW_HOME}/agents/kev-analyst/sessions/sessions.json" "$BACKUP_DIR"

# 2) Remove old daily memory note if present
if [[ -f "${OPENCLAW_HOME}/workspace/memory/2026-03-24.md" ]]; then
  rm -f "${OPENCLAW_HOME}/workspace/memory/2026-03-24.md"
  log "Removed legacy memory note: 2026-03-24.md"
fi

# 3) Clean legacy KEV references from MEMORY.md
MEMORY_FILE="${OPENCLAW_HOME}/workspace/MEMORY.md"
if ensure_file "$MEMORY_FILE"; then
  TMP_FILE="$(mktemp)"
  grep -Ev 'kev-lookup|/opt/apps/kevctem|KEV lookup|check kev|kev lookup|scripts/kev_lookup.py' "$MEMORY_FILE" > "$TMP_FILE" || true
  cp "$TMP_FILE" "$MEMORY_FILE"
  rm -f "$TMP_FILE"
  log "Cleaned legacy KEV references from MEMORY.md"
fi

# 4) Archive old session transcripts and reset session indexes
for agent in main biscuits kev-analyst; do
  SESSION_DIR="${OPENCLAW_HOME}/agents/${agent}/sessions"
  if [[ -d "$SESSION_DIR" ]]; then
    mkdir -p "${BACKUP_DIR}/${agent}-session-jsonl"

    shopt -s nullglob
    jsonl_files=("${SESSION_DIR}"/*.jsonl)
    shopt -u nullglob

    if (( ${#jsonl_files[@]} > 0 )); then
      mv "${SESSION_DIR}"/*.jsonl "${BACKUP_DIR}/${agent}-session-jsonl/"
      log "Archived ${agent} session jsonl files"
    fi

    printf '{}\n' > "${SESSION_DIR}/sessions.json"
    log "Reset ${agent} sessions.json"
  else
    log "Missing session dir for agent ${agent} (skipping)"
  fi
done

# 5) Optional: archive old local kev-lookup folders if they exist
mkdir -p "${BACKUP_DIR}/legacy-folders"
archive_dir_with_unique_name "/opt/apps/galapagos/kev-lookup" "${BACKUP_DIR}/legacy-folders" "galapagos-kev-lookup"
archive_dir_with_unique_name "/opt/apps/kevctem/kev-lookup" "${BACKUP_DIR}/legacy-folders" "kevctem-kev-lookup"

# 6) Restart OpenClaw gateway
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user restart openclaw-gateway
  log "Restarted openclaw-gateway"

  log "Gateway status:"
  systemctl --user status openclaw-gateway --no-pager || true
else
  log "systemctl not found; restart OpenClaw manually"
fi

log "Done"
log "Backups saved in: ${BACKUP_DIR}"
log "Now test in Telegram: /kev help"
