DROP TABLE IF EXISTS kev_xref;
DROP TABLE IF EXISTS kev_item;
DROP TABLE IF EXISTS daily_kev_top20;

CREATE TABLE kev_item (
  kev_item_id BIGINT NOT NULL AUTO_INCREMENT,
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
  first_seen_date DATE NOT NULL,
  last_seen_date DATE NOT NULL,
  is_active TINYINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (kev_item_id),
  UNIQUE KEY uq_kev_item_cve (cve_id),
  KEY idx_kev_item_active (is_active),
  KEY idx_kev_item_first_seen (first_seen_date),
  KEY idx_kev_item_last_seen (last_seen_date),
  KEY idx_kev_item_ransomware (known_ransomware_campaign_use)
);

CREATE TABLE kev_xref (
  kev_item_id BIGINT NOT NULL,
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
  refreshed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (kev_item_id),
  UNIQUE KEY uq_kev_xref_cve (cve_id),
  KEY idx_kev_xref_ransomware (known_ransomware_campaign_use),

  CONSTRAINT fk_kev_xref_item
    FOREIGN KEY (kev_item_id)
    REFERENCES kev_item (kev_item_id)
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