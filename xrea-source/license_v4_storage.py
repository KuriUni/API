"""Additive, independently versioned storage for License API v4."""

TABLES = {
    'license_v4_challenges': '''CREATE TABLE IF NOT EXISTS license_v4_challenges (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      challenge_id CHAR(32) NOT NULL,
      purpose VARCHAR(16) NOT NULL,
      nonce_hash CHAR(64) NOT NULL,
      device_key_thumbprint CHAR(64) NOT NULL,
      ip_hash CHAR(64) DEFAULT NULL,
      expires_at DATETIME NOT NULL,
      consumed_at DATETIME DEFAULT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id), UNIQUE KEY uq_license_v4_challenge_id (challenge_id),
      KEY idx_license_v4_challenge_expiry (expires_at,consumed_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci''',
    'license_v4_devices': '''CREATE TABLE IF NOT EXISTS license_v4_devices (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      license_id BIGINT UNSIGNED NOT NULL,
      device_hash CHAR(64) NOT NULL,
      device_label VARCHAR(120) DEFAULT NULL,
      public_key_pem TEXT NOT NULL,
      key_thumbprint CHAR(64) NOT NULL,
      key_algorithm VARCHAR(32) NOT NULL,
      app_version VARCHAR(40) DEFAULT NULL,
      bound_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      revoked_at DATETIME DEFAULT NULL,
      PRIMARY KEY (id), UNIQUE KEY uq_license_v4_device (license_id,device_hash),
      UNIQUE KEY uq_license_v4_key (license_id,key_thumbprint),
      KEY idx_license_v4_device_license (license_id,revoked_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci''',
    'license_v4_sessions': '''CREATE TABLE IF NOT EXISTS license_v4_sessions (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      session_id CHAR(32) NOT NULL,
      family_id CHAR(32) NOT NULL,
      license_id BIGINT UNSIGNED NOT NULL,
      device_id BIGINT UNSIGNED NOT NULL,
      access_token_hash CHAR(64) NOT NULL,
      refresh_token_hash CHAR(64) NOT NULL,
      scopes_json TEXT NOT NULL,
      access_expires_at DATETIME NOT NULL,
      refresh_expires_at DATETIME NOT NULL,
      token_version INT UNSIGNED NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      revoked_at DATETIME DEFAULT NULL,
      revoke_reason VARCHAR(80) DEFAULT NULL,
      PRIMARY KEY (id), UNIQUE KEY uq_license_v4_session_id (session_id),
      UNIQUE KEY uq_license_v4_access (access_token_hash), UNIQUE KEY uq_license_v4_refresh (refresh_token_hash),
      KEY idx_license_v4_session_family (family_id,revoked_at),
      KEY idx_license_v4_session_device (device_id,revoked_at),
      KEY idx_license_v4_access_exp (access_expires_at), KEY idx_license_v4_refresh_exp (refresh_expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci''',
    'license_v4_proofs': '''CREATE TABLE IF NOT EXISTS license_v4_proofs (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      proof_hash CHAR(64) NOT NULL,
      session_id CHAR(32) NOT NULL,
      action VARCHAR(32) NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id), UNIQUE KEY uq_license_v4_proof (proof_hash),
      KEY idx_license_v4_proof_expiry (expires_at), KEY idx_license_v4_proof_session (session_id,action,created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci''',
    'license_v4_refresh_history': '''CREATE TABLE IF NOT EXISTS license_v4_refresh_history (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      token_hash CHAR(64) NOT NULL,
      session_id CHAR(32) NOT NULL,
      family_id CHAR(32) NOT NULL,
      expires_at DATETIME NOT NULL,
      used_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id), UNIQUE KEY uq_license_v4_refresh_history (token_hash),
      KEY idx_license_v4_refresh_family (family_id,used_at), KEY idx_license_v4_refresh_expiry (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci''',
    'license_v4_offline_tickets': '''CREATE TABLE IF NOT EXISTS license_v4_offline_tickets (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      ticket_id CHAR(32) NOT NULL,
      license_id BIGINT UNSIGNED NOT NULL,
      device_id BIGINT UNSIGNED NOT NULL,
      session_id CHAR(32) NOT NULL,
      kid CHAR(24) NOT NULL,
      payload_hash CHAR(64) NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      revoked_at DATETIME DEFAULT NULL,
      PRIMARY KEY (id), UNIQUE KEY uq_license_v4_offline_ticket (ticket_id),
      KEY idx_license_v4_offline_session (session_id,revoked_at),
      KEY idx_license_v4_offline_expiry (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci''',
}

REQUIRED_COLUMNS = {
    'license_v4_challenges': ('challenge_id','purpose','nonce_hash','device_key_thumbprint','expires_at','consumed_at'),
    'license_v4_devices': ('license_id','device_hash','public_key_pem','key_thumbprint','key_algorithm','revoked_at'),
    'license_v4_sessions': ('session_id','family_id','license_id','device_id','access_token_hash','refresh_token_hash','access_expires_at','refresh_expires_at','token_version','revoked_at'),
    'license_v4_proofs': ('proof_hash','session_id','action','expires_at'),
    'license_v4_refresh_history': ('token_hash','session_id','family_id','expires_at','used_at'),
    'license_v4_offline_tickets': ('ticket_id','license_id','device_id','session_id','kid','payload_hash','expires_at','revoked_at'),
}


def ensure_schema(connection):
    with connection.cursor() as cursor:
        for statement in TABLES.values():
            cursor.execute(statement)
        names = tuple(TABLES)
        placeholders = ','.join(['%s'] * len(names))
        cursor.execute('SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.columns WHERE table_schema=DATABASE() AND TABLE_NAME IN (' + placeholders + ')', names)
        found = {}
        for row in cursor.fetchall():
            found.setdefault(str(row['TABLE_NAME']), set()).add(str(row['COLUMN_NAME']))
    for table, columns in REQUIRED_COLUMNS.items():
        if not set(columns).issubset(found.get(table, set())):
            raise RuntimeError('license_v4_schema_invalid')
    connection.commit()
    return {'ok': True, 'tables': list(TABLES)}
