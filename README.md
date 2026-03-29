# galapagos

## Overview

KEV Daily Risk Monitoring V2 is a separate project from the existing KEV workflow.

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