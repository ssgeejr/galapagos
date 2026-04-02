-- DROP OLD TABLES
DROP TABLE IF EXISTS kev_changes;
DROP TABLE IF EXISTS daily_kev_top20;
DROP TABLE IF EXISTS kev_run_data;
DROP TABLE IF EXISTS kev_run;


-- CREATE NEW TABLES

CREATE TABLE kev_run (
  kev_run_id BIGINT NOT NULL AUTO_INCREMENT,
  run_date DATE NOT NULL,
  PRIMARY KEY (kev_run_id),
  UNIQUE KEY uq_kev_run_date (run_date)
);

CREATE TABLE kev_run_data (
  kev_run_data_id BIGINT NOT NULL AUTO_INCREMENT,
  kev_run_id BIGINT NOT NULL,
  cve_id VARCHAR(20) NOT NULL,
  vendor_project VARCHAR(255) NULL,
  product VARCHAR(255) NULL,
  vulnerability_name VARCHAR(1024) NULL,
  date_added DATE NULL,
  due_date DATE NULL,
  short_description TEXT NULL,
  required_action TEXT NULL,
  notes TEXT NULL,
  known_ransomware_campaign_use TINYINT NOT NULL DEFAULT 0,

  PRIMARY KEY (kev_run_data_id),
  UNIQUE KEY uq_kev_run_data_run_cve (kev_run_id, cve_id),
  KEY idx_kev_run_data_run_id (kev_run_id),
  KEY idx_kev_run_data_cve (cve_id),

  CONSTRAINT fk_kev_run_data_run
    FOREIGN KEY (kev_run_id)
    REFERENCES kev_run (kev_run_id)
    ON DELETE CASCADE
);

CREATE TABLE daily_kev_top20 (
  id BIGINT NOT NULL AUTO_INCREMENT,
  run_date DATE NOT NULL,
  dtkey VARCHAR(8) NOT NULL,
  pluginid VARCHAR(20) NOT NULL,
  solution TEXT NULL,
  hosts INT NOT NULL,
  ransomware_flag TINYINT NOT NULL DEFAULT 0,
  priority_score INT NOT NULL,
  risk_rank INT NOT NULL,

  PRIMARY KEY (id),
  UNIQUE KEY uq_daily_kev_top20_run_rank (run_date, risk_rank),
  KEY idx_daily_kev_top20_run_date (run_date),
  KEY idx_daily_kev_top20_dtkey (dtkey),
  KEY idx_daily_kev_top20_pluginid (pluginid)
);

CREATE TABLE kev_changes (
  kev_change_id BIGINT NOT NULL AUTO_INCREMENT,
  kev_run_id BIGINT NOT NULL,
  kev_run_data_id BIGINT NOT NULL,

  PRIMARY KEY (kev_change_id),
  UNIQUE KEY uq_kev_changes_run_data (kev_run_id, kev_run_data_id),
  KEY idx_kev_changes_run_id (kev_run_id),
  KEY idx_kev_changes_run_data_id (kev_run_data_id),

  CONSTRAINT fk_kev_changes_run
    FOREIGN KEY (kev_run_id)
    REFERENCES kev_run (kev_run_id)
    ON DELETE CASCADE,

  CONSTRAINT fk_kev_changes_run_data
    FOREIGN KEY (kev_run_data_id)
    REFERENCES kev_run_data (kev_run_data_id)
    ON DELETE CASCADE
);