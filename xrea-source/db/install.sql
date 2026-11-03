-- Schema 039 redesigned physical model
-- 47 physical tables and 8 filtered API-compatibility views

SET NAMES utf8mb4;

SET FOREIGN_KEY_CHECKS=0;

CREATE TABLE IF NOT EXISTS `admin_audit_events` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `request_id` char(16) NOT NULL,
  `actor_hash` char(64) DEFAULT NULL,
  `role_name` varchar(64) DEFAULT NULL,
  `node_role` varchar(20) NOT NULL,
  `event_type` varchar(80) NOT NULL,
  `target_type` varchar(40) DEFAULT NULL,
  `target_id` varchar(80) DEFAULT NULL,
  `before_json` text DEFAULT NULL,
  `after_json` text DEFAULT NULL,
  `outcome` varchar(20) NOT NULL DEFAULT 'success',
  `ip_hash` char(64) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `prev_hash` char(64) NOT NULL,
  `event_hash` char(64) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_admin_audit_request_event` (`request_id`,`event_type`),
  KEY `idx_admin_audit_created` (`created_at`),
  KEY `idx_admin_audit_actor` (`actor_hash`,`created_at`),
  KEY `idx_admin_audit_target` (`target_type`,`target_id`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `admin_error_diagnostics` (
  `error_id` char(8) NOT NULL,
  `error_type` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `file_path` varchar(512) NOT NULL,
  `line_number` int(10) unsigned NOT NULL,
  `context_json` text NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`error_id`),
  KEY `idx_admin_error_diagnostics_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `admin_principals` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `credential_id_hash` char(64) NOT NULL,
  `display_name` varchar(120) NOT NULL,
  `role_name` varchar(64) NOT NULL DEFAULT 'security-admin',
  `status` varchar(20) NOT NULL DEFAULT 'active',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_login_at` datetime DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_admin_credential_hash` (`credential_id_hash`),
  KEY `idx_admin_status_role` (`status`,`role_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `admin_roles` (
  `role_name` varchar(64) NOT NULL,
  `permissions_json` text NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`role_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `admin_service_intakes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `request_code` char(12) NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `request_type` varchar(24) NOT NULL,
  `service_code` varchar(80) DEFAULT NULL,
  `related_reference` varchar(160) DEFAULT NULL,
  `summary` varchar(1000) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'received',
  `priority` varchar(12) NOT NULL DEFAULT 'normal',
  `assigned_admin_id` bigint(20) unsigned DEFAULT NULL,
  `due_at` date DEFAULT NULL,
  `notes_json` longtext DEFAULT NULL,
  `created_by_hash` char(64) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_admin_service_intake_code` (`request_code`),
  KEY `idx_admin_service_intake_status` (`status`,`updated_at`),
  KEY `idx_admin_service_intake_tenant` (`tenant_id`,`created_at`),
  KEY `idx_admin_service_intake_queue` (`status`,`priority`,`due_at`,`updated_at`),
  KEY `idx_admin_service_intake_assignee` (`assigned_admin_id`,`status`),
  CONSTRAINT `fk_admin_service_intake_tenant` FOREIGN KEY (`tenant_id`) REFERENCES `tenants` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `api_billing_invoices` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `invoice_number` varchar(40) NOT NULL,
  `account_tenant_id` bigint(20) unsigned NOT NULL,
  `billing_period` char(7) NOT NULL,
  `customer_name` varchar(160) NOT NULL,
  `issuer_name` varchar(160) NOT NULL,
  `issuer_registration_number` varchar(32) NOT NULL DEFAULT '',
  `issue_date` date NOT NULL,
  `due_date` date NOT NULL,
  `tax_rate_basis_points` int(10) unsigned NOT NULL DEFAULT 1000,
  `subtotal_units` bigint(20) NOT NULL,
  `tax_units` bigint(20) NOT NULL,
  `adjustment_units` bigint(20) NOT NULL DEFAULT 0,
  `total_units` bigint(20) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'draft',
  `notes` text DEFAULT NULL,
  `snapshot_json` longtext NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `issued_at` datetime DEFAULT NULL,
  `paid_at` datetime DEFAULT NULL,
  `voided_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_api_billing_invoice_number` (`invoice_number`),
  UNIQUE KEY `uq_api_billing_invoice_period` (`account_tenant_id`,`billing_period`),
  KEY `idx_api_billing_invoice_status` (`status`,`billing_period`),
  KEY `idx_api_billing_invoice_tenant` (`account_tenant_id`,`billing_period`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `archived_identity_records` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `legacy_table` varchar(64) NOT NULL,
  `legacy_row_hash` char(64) NOT NULL,
  `tenant_id` bigint unsigned DEFAULT NULL,
  `row_data_base64_json` longtext NOT NULL,
  `archived_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_archived_identity_row` (`legacy_table`,`legacy_row_hash`),
  KEY `idx_archived_identity_tenant` (`tenant_id`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `auth_attempts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `ip_hash` char(64) NOT NULL,
  `action` varchar(32) NOT NULL DEFAULT 'generic',
  `subject_type` varchar(32) NOT NULL DEFAULT 'ip',
  `subject_hash` char(64) DEFAULT NULL,
  `success` tinyint(1) NOT NULL DEFAULT 0,
  `error_code` varchar(64) DEFAULT NULL,
  `attempted_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_attempts_ip_time` (`ip_hash`,`attempted_at`),
  KEY `idx_attempts_action_subject_time` (`action`,`subject_type`,`subject_hash`,`attempted_at`),
  KEY `idx_attempts_success_time` (`success`,`attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `baas_batch_jobs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `request_key` varchar(100) NOT NULL,
  `status` varchar(20) NOT NULL,
  `requested_count` int(10) unsigned NOT NULL,
  `succeeded_count` int(10) unsigned NOT NULL DEFAULT 0,
  `failed_count` int(10) unsigned NOT NULL DEFAULT 0,
  `result_json` longtext DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `completed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_batch_tenant_key` (`tenant_id`,`request_key`),
  KEY `idx_batch_tenant` (`tenant_id`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `data_change_journal` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `entity_type` varchar(40) NOT NULL,
  `entity_id` bigint(20) unsigned NOT NULL,
  `operation` varchar(20) NOT NULL,
  `row_version` bigint(20) unsigned NOT NULL,
  `changed_at` datetime NOT NULL DEFAULT current_timestamp(),
  `payload_hash` char(64) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_change_entity_version` (`entity_type`,`entity_id`,`row_version`),
  KEY `idx_change_checkpoint` (`id`,`changed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `ha_fence_state` (
  `singleton_id` tinyint(3) unsigned NOT NULL,
  `epoch` bigint(20) unsigned NOT NULL DEFAULT 1,
  `writer_role` varchar(20) NOT NULL,
  `lease_id` char(32) DEFAULT NULL,
  `lease_expires_at` datetime DEFAULT NULL,
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`singleton_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `idempotency_keys` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL DEFAULT 1,
  `operation` varchar(40) NOT NULL,
  `request_key` varchar(100) NOT NULL,
  `response_json` text NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_idempotency_tenant_operation_key` (`tenant_id`,`operation`,`request_key`),
  KEY `idx_idempotency_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `issuance_items` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `engine_version` tinyint unsigned NOT NULL,
  `job_row_id` bigint(20) unsigned NOT NULL,
  `item_no` int(10) unsigned NOT NULL,
  `license_id` bigint(20) unsigned NOT NULL,
  `key_fingerprint` char(64) NOT NULL,
  `product_key_enc` text NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_issuance_item` (`engine_version`,`job_row_id`,`item_no`),
  UNIQUE KEY `uq_issuance_engine_license` (`engine_version`,`license_id`),
  KEY `idx_issuance_fingerprint` (`engine_version`,`key_fingerprint`),
  CONSTRAINT `fk_issuance_item_job` FOREIGN KEY (`engine_version`,`job_row_id`) REFERENCES `issuance_jobs` (`engine_version`,`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `issuance_jobs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `engine_version` tinyint unsigned NOT NULL,
  `job_id` char(32) NOT NULL,
  `request_id` char(16) NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `product_id` bigint(20) unsigned NOT NULL,
  `environment` varchar(16) NOT NULL,
  `license_mode` varchar(20) NOT NULL,
  `requested_count` int(10) unsigned NOT NULL,
  `processed_count` int(10) unsigned NOT NULL DEFAULT 0,
  `succeeded_count` int(10) unsigned NOT NULL DEFAULT 0,
  `failed_count` int(10) unsigned NOT NULL DEFAULT 0,
  `chunk_size` int(10) unsigned NOT NULL DEFAULT 10000,
  `engine_profile` varchar(40) NOT NULL DEFAULT 'unified-bulk-x20-v1',
  `next_item_no` int(10) unsigned NOT NULL DEFAULT 1,
  `request_key` varchar(100) NOT NULL,
  `request_hash` char(64) NOT NULL,
  `label` varchar(100) DEFAULT NULL,
  `max_devices` int(10) unsigned NOT NULL DEFAULT 1,
  `evaluation_days` int(10) unsigned DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  `status` varchar(24) NOT NULL DEFAULT 'queued',
  `error_code` varchar(80) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `started_at` datetime DEFAULT NULL,
  `heartbeat_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `speed_tier` varchar(20) DEFAULT NULL,
  `queue_priority` tinyint unsigned NOT NULL DEFAULT 10,
  `preemptions` int unsigned NOT NULL DEFAULT 0,
  `last_preempted_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_issuance_engine_id` (`engine_version`,`id`),
  UNIQUE KEY `uq_issuance_engine_job` (`engine_version`,`job_id`),
  UNIQUE KEY `uq_issuance_engine_request` (`engine_version`,`tenant_id`,`request_key`),
  KEY `idx_issuance_engine_queue` (`engine_version`,`status`,`queue_priority`,`created_at`,`id`),
  KEY `idx_issuance_tenant_status` (`tenant_id`,`status`,`engine_version`,`id`),
  KEY `idx_issuance_engine_client` (`engine_version`,`client_id`,`created_at`),
  CONSTRAINT `ck_issuance_engine` CHECK (`engine_version` IN (4,5,6))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `issuance_plans` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `engine_version` tinyint unsigned NOT NULL,
  `job_row_id` bigint unsigned DEFAULT NULL,
  `job_engine_version` tinyint unsigned DEFAULT NULL,
  `plan_id` char(24) NOT NULL,
  `job_id` char(32) NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `execution_mode` varchar(16) NOT NULL,
  `atomicity` varchar(16) NOT NULL,
  `requested_count` int(10) unsigned NOT NULL,
  `initial_chunk_size` int(10) unsigned NOT NULL,
  `planner_version` varchar(40) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_issuance_engine_plan` (`engine_version`,`plan_id`),
  UNIQUE KEY `uq_issuance_plan_job` (`engine_version`,`job_id`),
  KEY `idx_issuance_plan_tenant` (`tenant_id`,`created_at`,`id`),
  KEY `idx_issuance_plan_client` (`client_id`,`created_at`),
  KEY `idx_issuance_plan_link` (`job_engine_version`,`job_row_id`),
  CONSTRAINT `ck_issuance_plan_engine` CHECK (`engine_version` IN (5,6)),
  CONSTRAINT `fk_issuance_plan_job` FOREIGN KEY (`job_engine_version`,`job_row_id`) REFERENCES `issuance_jobs` (`engine_version`,`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `jpki_verifications` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `verification_hash` char(64) NOT NULL,
  `state_hash` char(64) NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `environment` varchar(16) NOT NULL,
  `nonce_hash` char(64) NOT NULL,
  `code_verifier_enc` text NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'pending',
  `subject_hash` char(64) DEFAULT NULL,
  `acr` varchar(32) DEFAULT NULL,
  `failure_code` varchar(48) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  `verified_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_jpki_verification_hash` (`verification_hash`),
  UNIQUE KEY `uq_jpki_state_hash` (`state_hash`),
  KEY `idx_jpki_tenant_client` (`tenant_id`,`client_id`,`created_at`),
  KEY `idx_jpki_expiry_status` (`expires_at`,`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `license_devices` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `license_id` bigint(20) unsigned NOT NULL,
  `device_hash` char(64) NOT NULL,
  `device_label` varchar(120) DEFAULT NULL,
  `access_token_hash` char(64) NOT NULL,
  `refresh_token_hash` char(64) NOT NULL,
  `access_expires_at` datetime NOT NULL,
  `refresh_expires_at` datetime NOT NULL,
  `first_activated_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_seen_at` datetime NOT NULL DEFAULT current_timestamp(),
  `revoked_at` datetime DEFAULT NULL,
  `last_ip_hash` char(64) DEFAULT NULL,
  `app_version` varchar(40) DEFAULT NULL,
  `token_version` int(11) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_license_device` (`license_id`,`device_hash`),
  UNIQUE KEY `uq_license_access_token` (`access_token_hash`),
  UNIQUE KEY `uq_license_refresh_token` (`refresh_token_hash`),
  KEY `idx_license_devices_license_revoked` (`license_id`,`revoked_at`),
  KEY `idx_license_devices_access_expires` (`access_expires_at`),
  KEY `idx_license_devices_refresh_expires` (`refresh_expires_at`),
  CONSTRAINT `fk_license_devices_license` FOREIGN KEY (`license_id`) REFERENCES `licenses` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `license_v3_challenges` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `challenge_id` char(32) NOT NULL,
  `purpose` varchar(20) NOT NULL,
  `nonce_hash` char(64) NOT NULL,
  `device_key_thumbprint` char(64) NOT NULL,
  `ip_hash` char(64) DEFAULT NULL,
  `expires_at` datetime NOT NULL,
  `consumed_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_license_v3_challenge_id` (`challenge_id`),
  KEY `idx_license_v3_challenge_expiry` (`expires_at`,`consumed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `license_v3_devices` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `license_id` bigint(20) unsigned NOT NULL,
  `device_hash` char(64) NOT NULL,
  `device_label` varchar(120) DEFAULT NULL,
  `public_key_pem` text NOT NULL,
  `key_thumbprint` char(64) NOT NULL,
  `key_algorithm` varchar(32) NOT NULL,
  `app_version` varchar(40) DEFAULT NULL,
  `bound_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_seen_at` datetime NOT NULL DEFAULT current_timestamp(),
  `revoked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_license_v3_device` (`license_id`,`device_hash`),
  UNIQUE KEY `uq_license_v3_key` (`license_id`,`key_thumbprint`),
  KEY `idx_license_v3_device_license` (`license_id`,`revoked_at`),
  KEY `idx_license_v3_device_thumbprint` (`key_thumbprint`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `license_v3_offline_tickets` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `ticket_id` char(32) NOT NULL,
  `license_id` bigint(20) unsigned NOT NULL,
  `device_id` bigint(20) unsigned NOT NULL,
  `session_id` char(32) NOT NULL,
  `kid` varchar(40) NOT NULL,
  `payload_hash` char(64) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `revoked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_license_v3_offline_ticket` (`ticket_id`),
  KEY `idx_license_v3_offline_license` (`license_id`,`expires_at`),
  KEY `idx_license_v3_offline_session` (`session_id`,`revoked_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `license_v3_proofs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `proof_hash` char(64) NOT NULL,
  `session_id` char(32) NOT NULL,
  `action` varchar(32) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_license_v3_proof` (`proof_hash`),
  KEY `idx_license_v3_proof_expiry` (`expires_at`),
  KEY `idx_license_v3_proof_session` (`session_id`,`action`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `license_v3_refresh_history` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `token_hash` char(64) NOT NULL,
  `session_id` char(32) NOT NULL,
  `family_id` char(32) NOT NULL,
  `expires_at` datetime NOT NULL,
  `used_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_license_v3_refresh_history` (`token_hash`),
  KEY `idx_license_v3_refresh_family` (`family_id`,`used_at`),
  KEY `idx_license_v3_refresh_expiry` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `license_v3_sessions` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `session_id` char(32) NOT NULL,
  `family_id` char(32) NOT NULL,
  `license_id` bigint(20) unsigned NOT NULL,
  `device_id` bigint(20) unsigned NOT NULL,
  `access_token_hash` char(64) NOT NULL,
  `refresh_token_hash` char(64) NOT NULL,
  `scopes_json` text NOT NULL,
  `access_expires_at` datetime NOT NULL,
  `refresh_expires_at` datetime NOT NULL,
  `token_version` int(10) unsigned NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_seen_at` datetime NOT NULL DEFAULT current_timestamp(),
  `revoked_at` datetime DEFAULT NULL,
  `revoke_reason` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_license_v3_session_id` (`session_id`),
  UNIQUE KEY `uq_license_v3_access` (`access_token_hash`),
  UNIQUE KEY `uq_license_v3_refresh` (`refresh_token_hash`),
  KEY `idx_license_v3_session_family` (`family_id`,`revoked_at`),
  KEY `idx_license_v3_session_device` (`device_id`,`revoked_at`),
  KEY `idx_license_v3_session_access_exp` (`access_expires_at`),
  KEY `idx_license_v3_session_refresh_exp` (`refresh_expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `licenses` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL DEFAULT 1,
  `product_id` bigint(20) unsigned DEFAULT NULL,
  `key_hash` char(64) NOT NULL,
  `label` varchar(100) DEFAULT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `max_devices` int(11) NOT NULL DEFAULT 1,
  `evaluation_days` int(11) DEFAULT NULL,
  `evaluation_started_at` datetime DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_reason` varchar(200) DEFAULT NULL,
  `deleted_by` char(64) DEFAULT NULL,
  `last_activated_at` datetime DEFAULT NULL,
  `last_seen_at` datetime DEFAULT NULL,
  `reissue_used_at` datetime DEFAULT NULL,
  `offline_lookup` char(20) DEFAULT NULL,
  `offline_secret_enc` text DEFAULT NULL,
  `offline_epoch` int(10) unsigned NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_licenses_key_hash` (`key_hash`),
  UNIQUE KEY `uq_licenses_offline_lookup` (`offline_lookup`),
  KEY `idx_licenses_tenant_deleted` (`tenant_id`,`deleted_at`,`id`),
  KEY `idx_licenses_tenant_product` (`tenant_id`,`product_id`,`deleted_at`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `offline_activation_requests` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `license_id` bigint(20) unsigned NOT NULL,
  `installation_id_hash` char(64) NOT NULL,
  `device_ref` char(20) NOT NULL,
  `expires_day` int(10) unsigned NOT NULL,
  `issued_by_hash` char(64) DEFAULT NULL,
  `request_ip_hash` char(64) DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `revocation_reason` varchar(200) DEFAULT NULL,
  `last_reconciled_at` datetime DEFAULT NULL,
  `issued_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_offline_installation` (`installation_id_hash`),
  KEY `idx_offline_license` (`license_id`,`issued_at`),
  KEY `idx_offline_ip` (`request_ip_hash`,`issued_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `phone_activation_requests` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `license_id` bigint(20) unsigned NOT NULL,
  `device_hash` char(64) NOT NULL,
  `installation_id` varchar(80) NOT NULL,
  `device_label` varchar(120) DEFAULT NULL,
  `app_version` varchar(40) DEFAULT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'requested',
  `requested_at` datetime NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  `email_enc` text DEFAULT NULL,
  `email_masked` varchar(254) DEFAULT NULL,
  `email_sent_at` datetime DEFAULT NULL,
  `confirmation_code_hash` char(64) DEFAULT NULL,
  `confirmation_code_expires_at` datetime DEFAULT NULL,
  `confirmation_code_issued_at` datetime DEFAULT NULL,
  `confirmation_code_issue_count` int(11) NOT NULL DEFAULT 0,
  `confirmation_fail_count` int(11) NOT NULL DEFAULT 0,
  `confirmed_at` datetime DEFAULT NULL,
  `last_seen_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_ip_hash` char(64) DEFAULT NULL,
  `confirmed_ip_hash` char(64) DEFAULT NULL,
  `cancelled_at` datetime DEFAULT NULL,
  `cancelled_reason` varchar(120) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_phone_activation_installation` (`installation_id`),
  KEY `idx_phone_activation_license_status` (`license_id`,`status`),
  KEY `idx_phone_activation_device` (`license_id`,`device_hash`),
  KEY `idx_phone_activation_expires` (`expires_at`),
  KEY `idx_phone_activation_code_expires` (`confirmation_code_expires_at`),
  CONSTRAINT `fk_phone_activation_requests_license` FOREIGN KEY (`license_id`) REFERENCES `licenses` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `product_key_issue_batches` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `batch_id` char(32) NOT NULL,
  `request_id` char(16) NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned DEFAULT NULL,
  `product_id` bigint(20) unsigned NOT NULL,
  `environment` varchar(16) NOT NULL,
  `api_version` varchar(32) NOT NULL DEFAULT 'product-key-issuance-v2',
  `source` varchar(16) NOT NULL DEFAULT 'ha-v2',
  `license_mode` varchar(20) NOT NULL,
  `requested_count` int(10) unsigned NOT NULL,
  `request_key` varchar(100) NOT NULL,
  `request_hash` char(64) NOT NULL,
  `response_enc` longtext DEFAULT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'pending',
  `issued_by_role` varchar(20) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `completed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_pk_issue_batch_id` (`batch_id`),
  UNIQUE KEY `uq_pk_issue_tenant_request` (`tenant_id`,`request_key`),
  KEY `idx_pk_issue_tenant_created` (`tenant_id`,`created_at`),
  KEY `idx_pk_issue_v3_tenant` (`tenant_id`,`api_version`,`source`,`created_at`),
  KEY `idx_pk_issue_status` (`status`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `product_key_issue_items` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `batch_row_id` bigint(20) unsigned NOT NULL,
  `item_no` int(10) unsigned NOT NULL,
  `license_id` bigint(20) unsigned NOT NULL,
  `key_fingerprint` char(64) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_pk_issue_batch_item` (`batch_row_id`,`item_no`),
  UNIQUE KEY `uq_pk_issue_license` (`license_id`),
  KEY `idx_pk_issue_item_fingerprint` (`key_fingerprint`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `products` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `code` varchar(64) NOT NULL,
  `name` varchar(160) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'active',
  `settings_json` text DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_products_tenant_code` (`tenant_id`,`code`),
  KEY `idx_products_tenant_status` (`tenant_id`,`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `recovery_approval_requests` (
  `request_id` char(32) NOT NULL,
  `requested_by` varchar(191) NOT NULL,
  `requested_at` datetime NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  `approved_by_first` varchar(191) DEFAULT NULL,
  `approved_by_second` varchar(191) DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `cancelled_at` datetime DEFAULT NULL,
  PRIMARY KEY (`request_id`),
  KEY `idx_recovery_pending` (`completed_at`,`cancelled_at`,`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `schema_compatibility_issues` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `node_role` varchar(20) NOT NULL,
  `table_name` varchar(64) NOT NULL,
  `column_name` varchar(64) NOT NULL,
  `detected_at` datetime NOT NULL DEFAULT current_timestamp(),
  `resolved_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_open_schema_issue` (`node_role`,`table_name`,`column_name`,`resolved_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `schema_migration_history` (
  `version` varchar(64) NOT NULL,
  `applied_at` datetime NOT NULL,
  `archived_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`version`),
  KEY `idx_schema_migration_history_archived` (`archived_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `schema_migrations` (
  `version` varchar(64) NOT NULL,
  `applied_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `subscriber_sdk_setup_codes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `production_tenant_id` bigint(20) unsigned NOT NULL,
  `code_prefix` varchar(20) NOT NULL,
  `code_hash` char(64) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'active',
  `expires_at` datetime NOT NULL,
  `sdk_key_ttl_hours` int(10) unsigned NOT NULL DEFAULT 168,
  `sdk_rate_limit_per_minute` int(10) unsigned NOT NULL DEFAULT 60,
  `request_key` varchar(100) DEFAULT NULL,
  `response_enc` longtext DEFAULT NULL,
  `issued_at` datetime NOT NULL DEFAULT current_timestamp(),
  `redeemed_at` datetime DEFAULT NULL,
  `redeemed_ip_hash` char(64) DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_subscriber_sdk_setup_hash` (`code_hash`),
  KEY `idx_subscriber_sdk_setup_tenant` (`production_tenant_id`,`status`,`issued_at`),
  KEY `idx_subscriber_sdk_setup_expiry` (`status`,`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_api_attempts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned DEFAULT NULL,
  `client_id` bigint(20) unsigned DEFAULT NULL,
  `key_prefix` varchar(12) NOT NULL DEFAULT '',
  `operation` varchar(64) NOT NULL,
  `outcome` varchar(32) NOT NULL,
  `status_code` smallint(5) unsigned NOT NULL,
  `ip_hash` char(64) NOT NULL,
  `issuance_session_id` char(32) DEFAULT NULL,
  `attempted_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_attempt_ip_time` (`ip_hash`,`attempted_at`),
  KEY `idx_attempt_tenant_time` (`tenant_id`,`attempted_at`),
  KEY `idx_attempt_client_session_time` (`client_id`,`issuance_session_id`,`attempted_at`),
  KEY `idx_attempt_client_time` (`client_id`,`attempted_at`,`issuance_session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_api_clients` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `name` varchar(120) NOT NULL,
  `key_prefix` char(12) NOT NULL,
  `key_hash` char(64) NOT NULL,
  `scopes_json` text NOT NULL,
  `key_kind` varchar(32) NOT NULL DEFAULT 'standard',
  `policy_json` text DEFAULT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'active',
  `rate_limit_per_minute` int(10) unsigned NOT NULL DEFAULT 120,
  `last_used_at` datetime DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `revoked_at` datetime DEFAULT NULL,
  `replacement_client_id` bigint(20) unsigned DEFAULT NULL,
  `grace_expires_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_tenant_api_key_hash` (`key_hash`),
  KEY `idx_tenant_api_prefix` (`key_prefix`),
  KEY `idx_tenant_api_tenant` (`tenant_id`,`status`),
  KEY `idx_tenant_api_kind` (`tenant_id`,`key_kind`,`status`),
  KEY `idx_tenant_api_retiring` (`status`,`grace_expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_api_usage` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `operation` varchar(64) NOT NULL,
  `status_code` smallint(5) unsigned NOT NULL,
  `request_id` char(16) NOT NULL,
  `ip_hash` char(64) NOT NULL,
  `used_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_usage_client_time` (`client_id`,`used_at`),
  KEY `idx_usage_tenant_time` (`tenant_id`,`used_at`,`operation`,`status_code`),
  KEY `idx_usage_tenant_id` (`tenant_id`,`id`),
  KEY `idx_usage_tenant_client_id` (`tenant_id`,`client_id`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_api_usage_daily` (
  `usage_day` date NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `operation` varchar(64) NOT NULL,
  `status_code` smallint(5) unsigned NOT NULL,
  `request_count` bigint(20) unsigned NOT NULL,
  PRIMARY KEY (`usage_day`,`tenant_id`,`client_id`,`operation`,`status_code`),
  KEY `idx_usage_daily_tenant_day` (`tenant_id`,`usage_day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_key_issue_session_items` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `session_row_id` bigint(20) unsigned NOT NULL,
  `item_no` int(10) unsigned NOT NULL,
  `license_id` bigint(20) unsigned NOT NULL,
  `request_key` varchar(100) NOT NULL,
  `request_id` char(16) NOT NULL,
  `key_fingerprint` char(64) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_tenant_issue_session_item` (`session_row_id`,`item_no`),
  UNIQUE KEY `uq_tenant_issue_session_request` (`session_row_id`,`request_key`),
  UNIQUE KEY `uq_tenant_issue_session_license` (`license_id`),
  KEY `idx_tenant_issue_fingerprint` (`key_fingerprint`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_key_issue_sessions` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `session_id` char(32) NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `product_id` bigint(20) unsigned NOT NULL,
  `environment` varchar(16) NOT NULL,
  `api_version` varchar(16) NOT NULL,
  `requested_count` int(10) unsigned NOT NULL,
  `completed_count` int(10) unsigned NOT NULL DEFAULT 0,
  `status` varchar(20) NOT NULL DEFAULT 'running',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `completed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_tenant_issue_session` (`tenant_id`,`session_id`),
  KEY `idx_tenant_issue_session_status` (`tenant_id`,`status`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_portal_key_reissues` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `account_tenant_id` bigint(20) unsigned NOT NULL,
  `passkey_id` bigint(20) unsigned NOT NULL,
  `request_hash` char(64) NOT NULL,
  `source_client_id` bigint(20) unsigned NOT NULL,
  `new_client_id` bigint(20) unsigned NOT NULL,
  `amount_units` bigint(20) unsigned NOT NULL,
  `billing_period` char(7) NOT NULL,
  `grace_expires_at` datetime NOT NULL,
  `response_expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_portal_key_request` (`tenant_id`,`request_hash`),
  UNIQUE KEY `uq_portal_key_new_client` (`new_client_id`),
  KEY `idx_portal_key_fee_account` (`account_tenant_id`,`billing_period`),
  KEY `idx_portal_key_fee_tenant` (`tenant_id`,`billing_period`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_sso_bootstrap_tickets` (
  `ticket_hash` char(64) NOT NULL,
  `subject_hash` char(64) NOT NULL,
  `oidc_sid` char(64) NOT NULL,
  `created_at` datetime NOT NULL,
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`ticket_hash`),
  KEY `idx_tenant_sso_ticket_expiry` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_sso_memberships` (
  `subject_hash` char(64) NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `source_client_id` bigint(20) unsigned NOT NULL,
  `scopes_json` text NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`subject_hash`,`tenant_id`),
  KEY `idx_tenant_sso_membership_tenant` (`tenant_id`,`subject_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_sso_sessions` (
  `token_hash` char(64) NOT NULL,
  `subject_hash` char(64) NOT NULL,
  `oidc_sid` char(64) NOT NULL,
  `tenant_id` bigint(20) unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `last_used_at` datetime DEFAULT NULL,
  `sso_checked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`token_hash`),
  KEY `idx_tenant_sso_session_subject` (`subject_hash`,`revoked_at`),
  KEY `idx_tenant_sso_session_expiry` (`expires_at`),
  KEY `idx_tenant_sso_session_sid` (`oidc_sid`,`revoked_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_webhook_deliveries` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `webhook_id` bigint(20) unsigned NOT NULL,
  `event_type` varchar(80) NOT NULL,
  `event_id` char(32) NOT NULL,
  `payload_json` longtext NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'pending',
  `attempt_count` int(10) unsigned NOT NULL DEFAULT 0,
  `next_attempt_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_status` smallint(5) unsigned DEFAULT NULL,
  `last_error` varchar(200) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `delivered_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_webhook_event` (`webhook_id`,`event_id`),
  KEY `idx_delivery_due` (`status`,`next_attempt_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenant_webhooks` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `url` varchar(500) NOT NULL,
  `secret_hash` char(64) NOT NULL,
  `secret_enc` text NOT NULL,
  `events_json` text NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'active',
  `failure_count` int(10) unsigned NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_webhook_tenant` (`tenant_id`,`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tenants` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `slug` varchar(63) NOT NULL,
  `name` varchar(160) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'active',
  `plan_code` varchar(40) NOT NULL DEFAULT 'standard',
  `environment` varchar(16) NOT NULL DEFAULT 'production',
  `parent_tenant_id` bigint(20) unsigned DEFAULT NULL,
  `max_products` int(10) unsigned NOT NULL DEFAULT 10,
  `max_licenses` int(10) unsigned NOT NULL DEFAULT 10000,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_tenants_slug` (`slug`),
  UNIQUE KEY `uq_tenant_parent_environment` (`parent_tenant_id`,`environment`),
  KEY `idx_tenants_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW `product_key_issue_jobs_v4` AS SELECT `id`,`job_id`,`request_id`,`tenant_id`,`client_id`,`product_id`,`environment`,`license_mode`,`requested_count`,`processed_count`,`succeeded_count`,`failed_count`,`chunk_size`,`speed_tier`,`queue_priority`,`preemptions`,`last_preempted_at`,`next_item_no`,`request_key`,`request_hash`,`label`,`max_devices`,`evaluation_days`,`expires_at`,`status`,`error_code`,`created_at`,`started_at`,`heartbeat_at`,`completed_at` FROM `issuance_jobs` WHERE `engine_version`=4 WITH CASCADED CHECK OPTION;

CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW `product_key_issue_v4_items` AS SELECT `id`,`job_row_id`,`item_no`,`license_id`,`key_fingerprint`,`product_key_enc`,`created_at` FROM `issuance_items` WHERE `engine_version`=4 WITH CASCADED CHECK OPTION;

CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW `product_key_issue_jobs_v5` AS SELECT `id`,`job_id`,`request_id`,`tenant_id`,`client_id`,`product_id`,`environment`,`license_mode`,`requested_count`,`processed_count`,`succeeded_count`,`failed_count`,`chunk_size`,`engine_profile`,`next_item_no`,`request_key`,`request_hash`,`label`,`max_devices`,`evaluation_days`,`expires_at`,`status`,`error_code`,`created_at`,`started_at`,`heartbeat_at`,`completed_at` FROM `issuance_jobs` WHERE `engine_version`=5 WITH CASCADED CHECK OPTION;

CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW `product_key_issue_v5_items` AS SELECT `id`,`job_row_id`,`item_no`,`license_id`,`key_fingerprint`,`product_key_enc`,`created_at` FROM `issuance_items` WHERE `engine_version`=5 WITH CASCADED CHECK OPTION;

CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW `product_key_issue_jobs_v6` AS SELECT `id`,`job_id`,`request_id`,`tenant_id`,`client_id`,`product_id`,`environment`,`license_mode`,`requested_count`,`processed_count`,`succeeded_count`,`failed_count`,`chunk_size`,`engine_profile`,`next_item_no`,`request_key`,`request_hash`,`label`,`max_devices`,`evaluation_days`,`expires_at`,`status`,`error_code`,`created_at`,`started_at`,`heartbeat_at`,`completed_at` FROM `issuance_jobs` WHERE `engine_version`=6 WITH CASCADED CHECK OPTION;

CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW `product_key_issue_v6_items` AS SELECT `id`,`job_row_id`,`item_no`,`license_id`,`key_fingerprint`,`product_key_enc`,`created_at` FROM `issuance_items` WHERE `engine_version`=6 WITH CASCADED CHECK OPTION;

CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW `product_key_issue_plans_v5` AS SELECT `id`,`plan_id`,`job_id`,`tenant_id`,`client_id`,`execution_mode`,`atomicity`,`requested_count`,`initial_chunk_size`,`planner_version`,`created_at` FROM `issuance_plans` WHERE `engine_version`=5 WITH CASCADED CHECK OPTION;

CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW `product_key_issue_plans_v6` AS SELECT `id`,`plan_id`,`job_id`,`tenant_id`,`client_id`,`execution_mode`,`atomicity`,`requested_count`,`initial_chunk_size`,`planner_version`,`created_at` FROM `issuance_plans` WHERE `engine_version`=6 WITH CASCADED CHECK OPTION;

INSERT IGNORE INTO `tenants`(id,slug,name,status,plan_code,max_products,max_licenses) VALUES(1,'tuti','TUTI','active','internal',100,1000000);

INSERT IGNORE INTO `products`(id,tenant_id,code,name,status) VALUES(1,1,'default','TUTI License','active');

INSERT IGNORE INTO `ha_fence_state`(singleton_id,epoch,writer_role) VALUES(1,1,'primary');

INSERT IGNORE INTO `admin_roles`(role_name,permissions_json) VALUES('viewer','["health.read","license.read","audit.read"]');

INSERT IGNORE INTO `admin_roles`(role_name,permissions_json) VALUES('operator','["health.read","license.read","license.issue","phone.manage","audit.read"]');

INSERT IGNORE INTO `admin_roles`(role_name,permissions_json) VALUES('security-admin','["passkey.manage","recovery.approve","audit.read"]');

INSERT IGNORE INTO `admin_roles`(role_name,permissions_json) VALUES('ha-admin','["ha.sync","ha.promote","ha.failback","backup.restore-test"]');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('014_sandbox_tenants');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('026_product_key_issuance_v5_native');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('027_license_api_v3_beta');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('028_product_key_issuance_v6_unified');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('032_admin_service_intakes');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('033_jpki_verifications');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('034_tenant_common_id_memberships');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('035_common_id_sso_authorization_code');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('036_tenant_sso_api_key_links');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('037_admin_error_diagnostics');

INSERT IGNORE INTO `schema_migrations`(version) VALUES('038_canonical_schema_performance');

SET FOREIGN_KEY_CHECKS=1;
