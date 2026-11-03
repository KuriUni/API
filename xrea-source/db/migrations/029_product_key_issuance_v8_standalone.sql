-- V8 owns new job and result tables. Existing issuance tables are untouched.
CREATE TABLE IF NOT EXISTS product_key_v8_jobs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  job_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_id CHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  tenant_id BIGINT UNSIGNED NOT NULL,
  client_id BIGINT UNSIGNED NOT NULL,
  product_id BIGINT UNSIGNED NOT NULL,
  environment VARCHAR(16) NOT NULL,
  license_mode VARCHAR(20) NOT NULL,
  requested_count INT UNSIGNED NOT NULL,
  processed_count INT UNSIGNED NOT NULL DEFAULT 0,
  succeeded_count INT UNSIGNED NOT NULL DEFAULT 0,
  failed_count INT UNSIGNED NOT NULL DEFAULT 0,
  chunk_size INT UNSIGNED NOT NULL DEFAULT 10000,
  label VARCHAR(100) DEFAULT NULL,
  max_devices INT UNSIGNED NOT NULL DEFAULT 1,
  evaluation_days INT UNSIGNED DEFAULT NULL,
  expires_at DATETIME DEFAULT NULL,
  idempotency_key VARCHAR(100) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'queued',
  error_code VARCHAR(64) DEFAULT NULL,
  engine_profile VARCHAR(40) NOT NULL DEFAULT 'v8-native-bulk-v1',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at DATETIME DEFAULT NULL,
  heartbeat_at DATETIME DEFAULT NULL,
  completed_at DATETIME DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_pk8_job_id (job_id),
  UNIQUE KEY uq_pk8_tenant_idem (tenant_id,idempotency_key),
  KEY idx_pk8_queue (status,created_at,id),
  KEY idx_pk8_tenant_status (tenant_id,status,created_at),
  KEY idx_pk8_client_created (client_id,created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS product_key_v8_items (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  job_row_id BIGINT UNSIGNED NOT NULL,
  item_no INT UNSIGNED NOT NULL,
  license_id BIGINT UNSIGNED NOT NULL,
  key_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  product_key_enc TEXT CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_pk8_item_no (job_row_id,item_no),
  UNIQUE KEY uq_pk8_license_id (license_id),
  KEY idx_pk8_fingerprint (key_fingerprint),
  CONSTRAINT fk_pk8_item_job FOREIGN KEY (job_row_id)
    REFERENCES product_key_v8_jobs(id) ON DELETE CASCADE,
  CONSTRAINT fk_pk8_item_license FOREIGN KEY (license_id)
    REFERENCES licenses(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO schema_migrations(version)
VALUES ('029_product_key_issuance_v8_standalone');
