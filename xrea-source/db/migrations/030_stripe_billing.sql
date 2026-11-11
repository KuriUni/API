-- Stripe hosted invoice payments for issued BaaS invoices (no email collection).
-- These tables stay outside the schema 039 plan; `POST /ha/migrate.php`
-- with {"scope":"stripe"} runs the same statements through stripe_billing.ensure_schema.

CREATE TABLE IF NOT EXISTS `stripe_invoice_payments` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `invoice_id` bigint(20) unsigned NOT NULL,
  `account_tenant_id` bigint(20) unsigned NOT NULL,
  `payer_tenant_id` bigint(20) unsigned NOT NULL,
  `checkout_session_id` varchar(120) DEFAULT NULL COMMENT 'Legacy column: stores Stripe Invoice ID (in_...) for invoice payments',
  `payment_intent_id` varchar(120) DEFAULT NULL,
  `amount_yen` int(10) unsigned NOT NULL,
  `currency` char(3) NOT NULL DEFAULT 'jpy',
  `mode` varchar(8) NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'creating',
  `checkout_url` varchar(512) NOT NULL DEFAULT '',
  `expires_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `failure_code` varchar(64) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_stripe_checkout_session` (`checkout_session_id`),
  KEY `idx_stripe_payment_invoice` (`invoice_id`,`status`),
  KEY `idx_stripe_payment_account` (`account_tenant_id`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `stripe_webhook_events` (
  `event_id` varchar(120) NOT NULL,
  `event_type` varchar(80) NOT NULL,
  `mode` varchar(8) NOT NULL DEFAULT '',
  `status` varchar(16) NOT NULL DEFAULT 'received',
  `invoice_id` bigint(20) unsigned DEFAULT NULL,
  `payment_id` bigint(20) unsigned DEFAULT NULL,
  `message` varchar(255) NOT NULL DEFAULT '',
  `received_at` datetime NOT NULL DEFAULT current_timestamp(),
  `processed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`event_id`),
  KEY `idx_stripe_event_status` (`status`,`received_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `stripe_billing_key_suspensions` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `invoice_id` bigint(20) unsigned NOT NULL,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `suspended_at` datetime NOT NULL DEFAULT current_timestamp(),
  `restored_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_stripe_billing_suspension` (`invoice_id`,`client_id`),
  KEY `idx_stripe_billing_suspension_client` (`client_id`,`restored_at`),
  KEY `idx_stripe_billing_suspension_invoice` (`invoice_id`,`restored_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `stripe_key_reissue_payments` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint(20) unsigned NOT NULL,
  `account_tenant_id` bigint(20) unsigned NOT NULL,
  `payer_tenant_id` bigint(20) unsigned NOT NULL,
  `passkey_id` bigint(20) unsigned NOT NULL DEFAULT 0,
  `request_hash` char(64) NOT NULL,
  `source_client_id` bigint(20) unsigned NOT NULL,
  `scopes_json` longtext NOT NULL,
  `environment` varchar(16) NOT NULL,
  `mode` varchar(8) NOT NULL,
  `amount_yen` int(10) unsigned NOT NULL,
  `currency` char(3) NOT NULL DEFAULT 'jpy',
  `checkout_session_id` varchar(120) DEFAULT NULL,
  `payment_intent_id` varchar(120) DEFAULT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'creating',
  `new_client_id` bigint(20) unsigned DEFAULT NULL,
  `checkout_url` varchar(512) NOT NULL DEFAULT '',
  `grace_expires_at` datetime DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `failure_code` varchar(64) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_key_reissue_session` (`checkout_session_id`),
  KEY `idx_key_reissue_request` (`tenant_id`,`request_hash`),
  KEY `idx_key_reissue_status` (`status`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
