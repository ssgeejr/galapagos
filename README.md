# Galapagos

## Overview

KEV Daily Risk Monitoring (V2) is a separate project from the existing KEV workflow.

- **V1 remains unchanged**
- **V2 is a separate test project**
- V2 uses:
  - **latest available Tenable data**
  - **daily KEV snapshots**
- V2 stores daily results in warehouse-style tables

The purpose of V2 is to generate a **daily top 20 risk list** using the latest Tenable snapshot and the current day’s KEV data.

---

## Data Sources

### Tenable
Tenable results are imported manually into MySQL on the existing schedule.

These imports remain the exposure baseline for V2.

### KEV
KEV data is pulled daily and stored as a daily snapshot.

---

## V2 Tables

### `daily_kev`

Stores the KEV catalog snapshot for a given run date.

```sql
CREATE TABLE daily_kev (
  kev_run_id BIGINT NOT NULL AUTO_INCREMENT,
  run_date DATE NOT NULL,
  cve_id VARCHAR(20) NOT NULL,
  vendor_project VARCHAR(255),
  product VARCHAR(255),
  vulnerability_name VARCHAR(1024),
  date_added DATE,
  due_date DATE,
  known_ransomware_campaign_use TINYINT NOT NULL DEFAULT 0,
  PRIMARY KEY (kev_run_id, cve_id),
  KEY idx_cve (cve_id),
  KEY idx_run_date (run_date),
  KEY idx_ransomware (known_ransomware_campaign_use)
);
```

---

### `daily_kev_top20`

Stores the daily top 20 risk results.

```sql
CREATE TABLE daily_kev_top20 (
  id BIGINT NOT NULL AUTO_INCREMENT,
  run_date DATE NOT NULL,
  kev_run_id BIGINT NOT NULL,
  dtkey VARCHAR(8) NOT NULL,

  pluginid VARCHAR(20) NOT NULL,
  solution TEXT,

  hosts INT NOT NULL,
  ransomware_flag TINYINT NOT NULL DEFAULT 0,
  priority_score INT NOT NULL,
  rank INT NOT NULL,

  PRIMARY KEY (id),
  KEY idx_run_date (run_date),
  KEY idx_kev_run (kev_run_id),
  KEY idx_dtkey (dtkey),
  KEY idx_rank (rank)
);
```

---

## Daily Workflow

1. Pull daily KEV data
2. Insert KEV snapshot into `daily_kev`
3. Get the KEV run key for that snapshot
4. Select the latest available Tenable `dtkey`
5. Join that Tenable dataset to the KEV snapshot
6. Score the results
7. Insert the top 20 into `daily_kev_top20`

---

## Current Scoring Logic

```
priority_score = hosts + (ransomware_flag * 100)
```

Where:

- `hosts` = count of distinct affected hosts
- `ransomware_flag` = 1 if the KEV match has known ransomware campaign use

---

## Query to Pull Current Top 20 (V1 Logic)

```sql
SELECT
  solution,
  pluginid,
  COUNT(DISTINCT host) AS hosts,
  MAX(kev_ransomware_flag) AS ransomware,
  COUNT(DISTINCT host) +
    (CASE WHEN MAX(kev_ransomware_flag) = 1 THEN 100 ELSE 0 END) AS priority_score
FROM scorecard
WHERE dtkey = (
  SELECT dtkey
  FROM scorecard
  ORDER BY rptdate DESC
  LIMIT 1
)
AND kev_flag = 1
GROUP BY solution, pluginid
ORDER BY priority_score DESC, hosts DESC
LIMIT 20;
```

---

## Purpose of `daily_kev_top20`

This table stores the top 20 risk list for each run date.

It preserves:

- the KEV snapshot used that day
- the Tenable snapshot used that day
- the ranked top 20 results for that day

---

## Scope

### In Scope
- daily KEV snapshot storage
- daily top 20 generation
- separate V2 project structure
- historical storage by date

### Out of Scope
- changes to V1
- changes to Tenable import schedule
- extra scoring fields
- `is_new`
- automation beyond the approved daily workflow

---

## Summary

V2 stores:

- a daily KEV snapshot in `daily_kev`
- a daily ranked top 20 in `daily_kev_top20`

It uses:

- the latest available Tenable `dtkey`
- the current day’s KEV snapshot
- the approved scoring logic

This provides a simple daily warehouse model for KEV-based risk reporting while keeping V1 unchanged.
