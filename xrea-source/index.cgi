#!/usr/bin/env python3
"""FastAPI gateway in the existing /license/ public root."""
import io
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

APP_DIR = Path(__file__).resolve().parent
PRIVATE_HOME = next(p.parent for p in APP_DIR.parents if p.name == 'public_html')
CONFIG = json.loads((APP_DIR / 'fastapi-runtime.json').read_text())
RUNTIME = PRIVATE_HOME / '.tuti-fastapi-latest' / CONFIG['runtime_release']
if sys.version_info[:3] != (3, 15, 2):
    environment = dict(os.environ)
    environment.pop('PYTHONPATH', None); environment.pop('PYTHONHOME', None)
    environment['LD_LIBRARY_PATH'] = str(RUNTIME / 'runtime/lib')
    for certificate in ('/etc/pki/tls/certs/ca-bundle.crt','/etc/ssl/certs/ca-certificates.crt'):
        if Path(certificate).is_file(): environment['SSL_CERT_FILE']=certificate; break
    executable = str(RUNTIME / 'runtime/bin/python3.15')
    os.execve(executable,[executable,'-I','-B',str(Path(__file__).resolve())],environment)
sys.dont_write_bytecode = True
sys.path[:0] = [str(APP_DIR), str(PRIVATE_HOME / '.tuti-fastapi' / CONFIG['release_id'] / 'vendor'), str(RUNTIME / 'vendor')]
os.environ['PYTHON_MIGRATION_PROFILE']='production'
os.environ['PYTHON_MIGRATION_URL_PREFIX']='/license'
os.environ['PYTHON_MIGRATION_PRIVATE_DIR']=str(PRIVATE_HOME / CONFIG['private_store'])
os.environ['TUTI_STATIC_ROOT']=str(APP_DIR)
import hashlib, hmac
probe = ''
if urlsplit(os.environ.get('REQUEST_URI','')).path in ('/license/index.cgi', '/license/' + CONFIG['probe_entry']):
    if not hmac.compare_digest(hashlib.sha256(os.environ.get('HTTP_X_TUTI_PROBE_TOKEN','').encode()).hexdigest(),CONFIG['probe_token_hash']):
        print('Status: 404 Not Found\r\nContent-Type: application/json\r\n\r\n{}'); sys.exit(0)
    probe=os.environ.get('HTTP_X_TUTI_PROBE_PATH','')
    if os.environ.get('REQUEST_METHOD') != 'GET' or probe not in CONFIG['probe_paths']:
        print('Status: 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{}'); sys.exit(0)
    os.environ['REQUEST_URI']='/license'+probe
    os.environ['QUERY_STRING']=''

from deployment_settings import load_deployment_config
load_deployment_config()
from request_metrics import RequestMetrics
metrics=RequestMetrics(dict(os.environ))
activation=metrics.activate()
try:
    if probe == '/_root-deploy/readiness':
        import database, fastapi, cryptography, pymysql, bcrypt
        from asgi import app
        connection=database.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute('START TRANSACTION READ ONLY')
                cursor.execute('SELECT 1 AS root_ready')
                assert cursor.fetchone()['root_ready']==1
            connection.rollback()
        finally:
            connection.close()
        from migration_config import secret_value
        from ha_handlers import _ready
        result={'native_routes':len(app.state.native_route_manifest),'db_readonly_select':True,
                'python':sys.version.split()[0],'fastapi':fastapi.__version__,
                'role':os.environ['PYTHON_MIGRATION_HA_ROLE'],
                'ha_ready':_ready(),
                'sso_configured':len(secret_value('admin_oidc_sso_client_secret'))>=32}
        metrics.status=200
        print('Content-Type: application/json\r\nCache-Control: no-store\r\n\r\n'+json.dumps(result))
    else:
        from fastapi_cgi import application
        metrics.bootstrap_complete()
        application=metrics.wrap(application)
        environ=dict(os.environ)
        if environ.get('REDIRECT_STATUS')=='200': environ.pop('REDIRECT_STATUS',None)
        path=urlsplit(environ.get('REQUEST_URI','/')).path
        environ['PATH_INFO']=path[len('/license'):] if path=='/license' or path.startswith('/license/') else path
        environ['PATH_INFO']=environ['PATH_INFO'] or '/'
        length=int(environ.get('CONTENT_LENGTH') or '0')
        if length<0 or length>50*1024*1024:
            metrics.status=413
            print('Status: 413 Content Too Large\r\nContent-Type: application/json\r\n\r\n{"ok":false,"error":"request_too_large"}')
            sys.exit(0)
        environ['wsgi.input']=io.BytesIO(sys.stdin.buffer.read(length))
        captured=[]
        def start_response(status, headers, exc_info=None): captured.append((status,headers))
        chunks=iter(application(environ,start_response))
        first=next(chunks,b'')
        status,headers=captured[0]
        headers=metrics.sync_response_id(first,headers)
        metrics.status=int(status.split()[0])
        headers += [('X-TUTI-Framework','fastapi'),('X-TUTI-FastAPI-Release',CONFIG['release_id']),
                    ('X-TUTI-FastAPI-Entry','index.cgi'),('X-TUTI-Python-Version',sys.version.split()[0])]
        sys.stdout.buffer.write(('\r\n'.join(['Status: '+status]+[k+': '+v for k,v in headers])+'\r\n\r\n').encode('latin-1'))
        import itertools
        for chunk in itertools.chain((first,),chunks):
            if environ.get('REQUEST_METHOD')!='HEAD': sys.stdout.buffer.write(chunk)
        if hasattr(chunks,'close'): chunks.close()
except Exception as error:
    metrics.fail(error)
    metrics.status=500
    print('Status: 500 Internal Server Error\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n'+json.dumps({'ok':False,'error':'internal_error'}))
    private=Path(os.environ['PYTHON_MIGRATION_PRIVATE_DIR'])/'runtime'
    private.mkdir(mode=0o700,exist_ok=True)
    failure=private/'root-fastapi-error.json'
    import traceback
    failure.write_text(json.dumps({'type':type(error).__name__,'frames':[{'file':Path(frame.filename).name,'line':frame.lineno} for frame in traceback.extract_tb(sys.exc_info()[2])]}))
    failure.chmod(0o600)
finally:
    metrics.deactivate(activation)
    metrics.finish()
