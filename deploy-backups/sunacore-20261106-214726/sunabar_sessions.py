"""Isolated, database-backed demo device sessions for Sunabar."""
import hashlib
import re
import secrets
import time

ACCESS_TTL = 3600
REFRESH_TTL = 7 * 86400


def _hash(value):
    return hashlib.sha256(value.encode('ascii')).hexdigest()


def _device(data, error):
    value = str(data.get('device_fingerprint') or data.get('device_id') or '')
    if not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', value):
        raise error(422, 'invalid_device_id', 'Use a device ID of 1–128 ASCII letters, digits, dots, colons, underscores or hyphens.')
    return _hash(value)


def _token(data, field, prefix, error):
    value = data.get(field)
    if not isinstance(value, str) or not re.fullmatch(prefix + r'\.[A-Za-z0-9_-]{43}', value):
        raise error(401, 'invalid_session_token')
    return _hash(value)


def _new_tokens(expiry, now):
    return ('sunabar_access.' + secrets.token_urlsafe(32),
            'sunabar_refresh.' + secrets.token_urlsafe(32),
            min(now + ACCESS_TTL, expiry), min(now + REFRESH_TTL, expiry))


def _reply(response, data):
    return response(200, {'ok': True, 'api_version': 'sunabar-v1', 'data': data})


def handle_session(path, identity, data, connect, response, error):
    workspace = identity['workspace']
    device_hash = _device(data, error)
    now = int(time.time())
    connection = connect()
    try:
        with connection.cursor() as cursor:
            if path == '/api/v1/activate':
                key = data.get('license_key') or data.get('product_key')
                if not isinstance(key, str) or len(key) > 4096 or not key.isascii() or not key:
                    raise error(422, 'invalid_license_key')
                cursor.execute('SELECT license_id, product_id, status, expires_at, max_devices FROM sunabar_licenses WHERE workspace_id=%s AND key_hash=%s FOR UPDATE', (workspace, _hash(key)))
                license_row = cursor.fetchone()
                if not license_row or license_row['status'] != 'active' or int(license_row['expires_at']) <= now:
                    raise error(401, 'license_unavailable')
                license_id = license_row['license_id']
                cursor.execute('SELECT id, revoked_at, refresh_expires_at FROM sunabar_sessions WHERE workspace_id=%s AND license_id=%s AND device_hash=%s FOR UPDATE', (workspace, license_id, device_hash))
                old = cursor.fetchone()
                cursor.execute('SELECT COUNT(*) AS count FROM sunabar_sessions WHERE workspace_id=%s AND license_id=%s AND revoked_at IS NULL AND refresh_expires_at>%s', (workspace, license_id, now))
                active_count = int(cursor.fetchone()['count'])
                already_active = old and old['revoked_at'] is None and int(old['refresh_expires_at']) > now
                if not already_active and active_count >= int(license_row['max_devices']):
                    raise error(409, 'device_limit_reached')
                session_expiry = min(int(license_row['expires_at']), int(identity['exp']))
                access, refresh, access_exp, refresh_exp = _new_tokens(session_expiry, now)
                if old:
                    cursor.execute('UPDATE sunabar_sessions SET access_hash=%s, refresh_hash=%s, access_expires_at=%s, refresh_expires_at=%s, revoked_at=NULL WHERE id=%s', (_hash(access), _hash(refresh), access_exp, refresh_exp, old['id']))
                else:
                    cursor.execute('INSERT INTO sunabar_sessions (workspace_id, license_id, device_hash, access_hash, refresh_hash, access_expires_at, refresh_expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)', (workspace, license_id, device_hash, _hash(access), _hash(refresh), access_exp, refresh_exp))
                cursor.execute('INSERT INTO sunabar_audit_events (workspace_id,event_type,entity_id,created_at) VALUES (%s,%s,%s,%s)', (workspace, 'session.activated', license_id, now))
                connection.commit()
                return _reply(response, {'license_id': license_id, 'product_id': license_row['product_id'], 'session': {'access_token': access, 'refresh_token': refresh, 'token_type': 'Bearer', 'access_expires_at': access_exp, 'refresh_expires_at': refresh_exp}})

            access_check = path == '/api/v1/session/check'
            token_field = 'access_token' if access_check else 'refresh_token'
            token_hash = _token(data, token_field, 'sunabar_access' if access_check else 'sunabar_refresh', error)
            column = 'access_hash' if access_check else 'refresh_hash'
            lock = '' if access_check else ' FOR UPDATE'
            cursor.execute('SELECT s.id, s.license_id, s.revoked_at, s.access_expires_at, s.refresh_expires_at, l.status, l.expires_at AS license_expires_at FROM sunabar_sessions s JOIN sunabar_licenses l ON l.license_id=s.license_id AND l.workspace_id=s.workspace_id WHERE s.workspace_id=%s AND s.device_hash=%s AND s.' + column + '=%s' + lock, (workspace, device_hash, token_hash))
            row = cursor.fetchone()
            expiry_field = 'access_expires_at' if access_check else 'refresh_expires_at'
            if not row or row['revoked_at'] is not None or int(row[expiry_field]) <= now:
                raise error(401, 'invalid_session_token')
            if path == '/api/v1/session/deactivate':
                cursor.execute('UPDATE sunabar_sessions SET revoked_at=%s WHERE id=%s', (now, row['id']))
                cursor.execute('INSERT INTO sunabar_audit_events (workspace_id,event_type,entity_id,created_at) VALUES (%s,%s,%s,%s)', (workspace, 'session.deactivated', row['license_id'], now))
                connection.commit()
                return _reply(response, {'license_id': row['license_id'], 'status': 'deactivated'})
            if row['status'] != 'active' or int(row['license_expires_at']) <= now:
                raise error(401, 'license_unavailable')
            if access_check:
                return _reply(response, {'valid': True, 'status': 'active', 'license_id': row['license_id'], 'access_expires_at': int(row['access_expires_at'])})
            session_expiry = min(int(row['license_expires_at']), int(identity['exp']))
            access, refresh, access_exp, refresh_exp = _new_tokens(session_expiry, now)
            cursor.execute('UPDATE sunabar_sessions SET access_hash=%s, refresh_hash=%s, access_expires_at=%s, refresh_expires_at=%s WHERE id=%s', (_hash(access), _hash(refresh), access_exp, refresh_exp, row['id']))
            cursor.execute('INSERT INTO sunabar_audit_events (workspace_id,event_type,entity_id,created_at) VALUES (%s,%s,%s,%s)', (workspace, 'session.refreshed', row['license_id'], now))
            connection.commit()
            return _reply(response, {'license_id': row['license_id'], 'session': {'access_token': access, 'refresh_token': refresh, 'token_type': 'Bearer', 'access_expires_at': access_exp, 'refresh_expires_at': refresh_exp}})
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
