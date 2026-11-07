"""Domain schema 039 installer/validator matching the current PHP contract."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = '039_domain_storage_redesign'


def import_row(table, row, legacy_ids=False):
    target, engine = table, None
    for pattern, physical in ((r'product_key_issue_jobs_v([456])','issuance_jobs'),
                              (r'product_key_issue_v([456])_items','issuance_items'),
                              (r'product_key_issue_plans_v([56])','issuance_plans')):
        match=re.fullmatch(pattern,table)
        if match:
            target,engine=physical,int(match[1]);break
    if engine is None:return target,dict(row)
    row=dict(row)
    if legacy_ids:
        for name in ('id','job_row_id') if target=='issuance_items' else ('id',):
            if row.get(name) is None:continue
            value=row[name]
            if isinstance(value,bool) or not re.fullmatch('[0-9]+',str(value)):
                raise RuntimeError('legacy_issuance_id_out_of_range')
            value=int(value)
            if not 1<=value<=(2**63-1-2)//4:raise RuntimeError('legacy_issuance_id_out_of_range')
            row[name]=value*4+engine-4
    return target,{'engine_version':engine,**row}


def link_plans(cursor):
    cursor.execute('UPDATE issuance_plans p JOIN issuance_jobs j ON j.engine_version=p.engine_version AND j.tenant_id=p.tenant_id AND j.job_id=p.job_id SET p.job_engine_version=j.engine_version,p.job_row_id=j.id WHERE p.job_row_id IS NULL')
    cursor.execute('UPDATE issuance_plans p JOIN issuance_jobs j ON j.engine_version=4 AND j.tenant_id=p.tenant_id AND j.job_id=p.job_id SET p.job_engine_version=j.engine_version,p.job_row_id=j.id WHERE p.engine_version=5 AND p.job_row_id IS NULL')


def load_plan():
    plan = json.loads((ROOT/'schema39-plan.json').read_text(encoding='utf-8'))
    if plan.get('version') != VERSION or len(plan.get('tables', [])) != 47 or len(plan.get('views', {})) != 8:
        raise RuntimeError('storage_plan_invalid')
    return plan


def validate(cursor, plan):
    object_names = tuple(dict.fromkeys([*plan['tables'], *plan['views']]))
    object_placeholders = ','.join(['%s'] * len(object_names))
    cursor.execute('SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.tables WHERE table_schema=DATABASE() AND TABLE_NAME IN (' + object_placeholders + ')', object_names)
    objects = {r['TABLE_NAME']: r['TABLE_TYPE'] for r in cursor.fetchall()}
    for name in plan['tables']:
        if objects.get(name) != 'BASE TABLE':
            raise RuntimeError('storage_table_missing:'+name)
    for name in plan['views']:
        if objects.get(name) != 'VIEW':
            raise RuntimeError('storage_view_missing:'+name)
    column_names = tuple(dict.fromkeys([*plan['physical_columns'], *plan['views']]))
    column_placeholders = ','.join(['%s'] * len(column_names))
    cursor.execute('SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.columns WHERE table_schema=DATABASE() AND TABLE_NAME IN (' + column_placeholders + ') ORDER BY TABLE_NAME,ORDINAL_POSITION', column_names)
    columns = {}
    for row in cursor.fetchall():
        columns.setdefault(row['TABLE_NAME'], []).append(row['COLUMN_NAME'])
    for name, expected in plan['physical_columns'].items():
        if columns.get(name, []) != expected:
            raise RuntimeError('storage_columns_mismatch:'+name)
    for name, view in plan['views'].items():
        if columns.get(name, []) != view['columns']:
            raise RuntimeError('storage_projection_mismatch:'+name)
    view_names = tuple(plan['views'])
    view_placeholders = ','.join(['%s'] * len(view_names))
    cursor.execute('SELECT TABLE_NAME,CHECK_OPTION,IS_UPDATABLE,SECURITY_TYPE FROM information_schema.views WHERE table_schema=DATABASE() AND TABLE_NAME IN (' + view_placeholders + ')', view_names)
    found = set()
    for row in cursor.fetchall():
        if row['TABLE_NAME'] not in plan['views']:
            continue
        if (row['CHECK_OPTION'], row['IS_UPDATABLE'], row['SECURITY_TYPE']) != ('CASCADED', 'YES', 'INVOKER'):
            raise RuntimeError('storage_view_not_isolated:'+row['TABLE_NAME'])
        found.add(row['TABLE_NAME'])
    if len(found) != 8:
        raise RuntimeError('storage_views_incomplete')
    return {'physical_tables': 47, 'compatibility_views': 8}


def run_migrations(connection):
    plan = load_plan()
    with connection.cursor() as cursor:
        cursor.execute('SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema=DATABASE()')
        objects = {r['TABLE_NAME'] for r in cursor.fetchall()}
        fresh = not objects
        if fresh:
            # Canonical install.sql has no routines or embedded semicolons;
            # preserve its statement order and the PHP installer's semantics.
            for statement in (ROOT/'schema39-install.sql').read_text(encoding='utf-8').split(';'):
                if statement.strip():
                    cursor.execute(statement.strip())
        else:
            if 'schema_migrations' not in objects:
                raise RuntimeError('controlled_data_migration_required')
            cursor.execute('SELECT COUNT(*) AS n FROM schema_migrations WHERE version=%s', (VERSION,))
            if int(cursor.fetchone()['n']) != 1:
                raise RuntimeError('controlled_data_migration_required')
        storage = validate(cursor, plan)
        if fresh:
            cursor.execute('INSERT IGNORE INTO schema_migrations(version) VALUES(%s)', (VERSION,))
            cursor.execute('INSERT IGNORE INTO schema_migration_history(version,applied_at) SELECT version,applied_at FROM schema_migrations')
        cursor.execute('SELECT version,applied_at FROM schema_migrations ORDER BY version')
        versions = cursor.fetchall()
        for row in versions:
            if hasattr(row.get('applied_at'), 'isoformat'):
                row['applied_at'] = row['applied_at'].isoformat(sep=' ')
        cursor.execute('SELECT COUNT(*) AS n FROM schema_migration_history')
        history = int(cursor.fetchone()['n'])
    connection.commit()
    return {'ok': True, 'version': VERSION, 'storage_model': 'domain-039',
            'migrations': versions, 'migration_history_count': history,
            'legacy_columns': [], 'index_present': True, 'fast_path': not fresh, **storage}
