# kev-lookup Skill

Automatically check for new CISA Known Exploited Vulnerabilities.

## Purpose
- Download latest KEV JSON from CISA
- Compare with previous version
- Report new/removed/updated CVEs
- Save summary markdown file

## Working Directory
`/opt/apps/kevctem`

## Trigger Phrases
- "lookup any new kevs"
- "check kev"
- "new kev updates"
- "run kev diff"
- "cisa kev"
- "kev lookup"
- "show me new known exploited vulnerabilities"

## Required Tools
- exec
- read
- write

## Usage
```
lookup any new kevs
```

## Output
- Console summary with CVE table
- Markdown summary saved to `kev-summary-MMDDYYYY.md`

## First Run Behavior
If no previous KEV file exists, downloads and reports total CVE count.

## Implementation
- Script: `/opt/apps/kevctem/scripts/kev_lookup.py`
- JSON files: `/opt/apps/kevctem/kev-MMDDYYYY.json`
- Summaries: `/opt/apps/kevctem/kev-summary-MMDDYYYY.md`