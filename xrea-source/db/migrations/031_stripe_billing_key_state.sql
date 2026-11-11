-- Preserve each API key's pre-billing state so successful settlement can
-- restore only keys that were active/retiring before billing suspension.
-- Safe to run on installations where 030 has already created the table.

ALTER TABLE `stripe_billing_key_suspensions`
  ADD COLUMN IF NOT EXISTS `previous_status` varchar(16) NOT NULL DEFAULT 'active' AFTER `client_id`;
