"""Verified tenant display data and provider session validation."""
import json
import re

ALLOWED_SCOPES = ('tenant:read', 'products:write', 'licenses:read', 'licenses:write')


def public_contract(row):
    def scopes(name):
        try:
            value = json.loads(str(row.get(name) or ''))
            return value if isinstance(value, list) else []
        except (ValueError, TypeError):
            return []
    membership, linked = scopes('scopes_json'), scopes('linked_scopes_json')
    allowed = [s for s in ALLOWED_SCOPES if s in membership and s in linked]
    if 'tenant:read' not in allowed:
        return None
    environment = 'sandbox' if row.get('parent_tenant_id') else str(row.get('environment') or '').strip().lower()
    if environment not in {'production', 'sandbox'}:
        return None
    return {'tenant_id': int(row['tenant_id']), 'slug': str(row['slug']),
            'name': str(row.get('tenant_name', row['slug'])), 'environment': environment,
            'scopes': allowed, 'source_client_id': int(row['source_client_id']),
            'key_name': str(row.get('key_name') or ''), 'key_prefix': str(row.get('key_prefix') or '')[:12],
            'source': str(row.get('grant_source') or 'membership'), 'grant_id': str(row.get('grant_id') or '')}


def initial_contract(memberships):
    return memberships[0] if len(memberships) == 1 else None


def provider_active(sid):
    if re.fullmatch('[a-f0-9]{64}', str(sid)) is None:
        return False
    try:
        from admin_oidc import session_active, TENANT_CLIENT_ID
        return bool(session_active(sid, TENANT_CLIENT_ID))
    except Exception:
        return False


def validate_provider(connection, session, token_hash):
    active = provider_active(str(session.get('oidc_sid') or ''))
    with connection.cursor() as cursor:
        cursor.execute('UPDATE tenant_sso_sessions SET '+
                       ('sso_checked_at=UTC_TIMESTAMP()' if active else 'revoked_at=UTC_TIMESTAMP()')+
                       ' WHERE token_hash=%s', (token_hash,))
    connection.commit()
    return active


def memberships(connection, subject_hash):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT m.tenant_id,m.source_client_id,m.scopes_json,c.scopes_json linked_scopes_json,"
            "c.name key_name,c.key_prefix,t.name tenant_name,t.slug,t.status,t.environment,t.parent_tenant_id "
            "FROM tenant_sso_memberships m JOIN tenants t ON t.id=m.tenant_id AND t.status='active' "
            "JOIN tenant_api_clients c ON c.id=m.source_client_id AND c.tenant_id=m.tenant_id "
            "AND c.status IN ('active','retiring') AND c.key_hash IS NOT NULL AND c.key_hash<>'' "
            "AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>UTC_TIMESTAMP()) "
            "AND (c.status='active' OR c.grace_expires_at>UTC_TIMESTAMP()) "
            "WHERE m.subject_hash=%s ORDER BY m.created_at,m.tenant_id", (subject_hash,))
        permanent = cursor.fetchall()
        try:
            cursor.execute(
                "SELECT g.tenant_id,g.source_client_id,g.scopes_json,c.scopes_json linked_scopes_json,"
                "c.name key_name,c.key_prefix,t.name tenant_name,t.slug,t.status,t.environment,t.parent_tenant_id,"
                "'temporary' grant_source,g.grant_id FROM tenant_sso_temporary_grants g "
                "JOIN tenants t ON t.id=g.tenant_id AND t.status='active' "
                "JOIN tenant_api_clients c ON c.id=g.source_client_id AND c.tenant_id=g.tenant_id "
                "AND c.status IN ('active','retiring') AND c.key_hash IS NOT NULL AND c.key_hash<>'' "
                "AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>UTC_TIMESTAMP()) "
                "AND (c.status='active' OR c.grace_expires_at>UTC_TIMESTAMP()) "
                "WHERE g.subject_hash=%s AND g.expires_at>UTC_TIMESTAMP() AND g.revoked_at IS NULL "
                "ORDER BY g.created_at,g.tenant_id", (subject_hash,))
            temporary = cursor.fetchall()
        except Exception as exc:
            # Deployments can briefly run older schemas during a rolling upgrade.
            if 'tenant_sso_temporary_grants' not in str(exc).lower():
                raise
            temporary = []
        return [contract for row in list(permanent) + list(temporary)
                if (contract := public_contract(row)) is not None]
