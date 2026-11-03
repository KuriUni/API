"""MNSL release signing; private key remains in SSO's non-public DATA directory."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import urllib.request

NODES = {'https://2415.jp/license', 'https://backup.2415.jp/license', 'https://main.2415.jp/license'}
FIELDS = ('schema','product','channel','version','revision','package_name','sha256','size','published_utc','terms_version','requires_reconsent','mandatory','release_notes')


def key_path(data):
    return Path(data) / 'mnsl-release-signing-v1.pem'


def provision(data):
    import fcntl
    data = Path(data).resolve()
    if 'public_html' in data.parts:
        raise RuntimeError('private_storage_required')
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (data/'mnsl-signing.lock').open('a+b') as lock:
        os.chmod(str(data/'mnsl-signing.lock'), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        target = key_path(data)
        if not target.exists():
            fd, name = tempfile.mkstemp(prefix='.mnsl-key-', dir=str(data))
            os.close(fd)
            try:
                subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=90)
                os.chmod(name, 0o600)
                os.replace(name, str(target))
            finally:
                if os.path.exists(name):
                    os.unlink(name)
        os.chmod(str(target), 0o600)
    return public_key(data)


def public_key(data):
    key = str(key_path(data))
    der = subprocess.run(['openssl','pkey','-in',key,'-pubout','-outform','DER'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10).stdout
    modulus = subprocess.run(['openssl','rsa','-in',key,'-noout','-modulus'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10).stdout.decode().strip().split('=',1)[1]
    raw = bytes.fromhex(modulus)
    if len(raw) != 384:
        raise RuntimeError('unexpected_key_size')
    xml = '<RSAKeyValue><Modulus>'+base64.b64encode(raw).decode()+'</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'
    return {'ok':True,'key_id':hashlib.sha256(der).hexdigest(),'algorithm':'RSA-3072-SHA256','public_key_xml':xml}


def canonical(m):
    if not isinstance(m,dict) or set(m) != set(FIELDS):
        raise ValueError('invalid_manifest_fields')
    if type(m['schema']) is not int or m['schema'] != 1 or m['product'] != 'MyNumberSmartLogin' or m['channel'] not in ('stable','beta'):
        raise ValueError('invalid_manifest_product')
    if not isinstance(m['version'],str) or not re.fullmatch(r'\d{1,5}\.\d{1,5}(?:\.\d{1,5}){0,2}',m['version']):
        raise ValueError('invalid_version')
    if type(m['revision']) is not int or not 0 < m['revision'] < 2**63 or type(m['size']) is not int or not 0 < m['size'] < 2**63:
        raise ValueError('invalid_revision_or_size')
    if m['package_name'] != 'MNSL-{}-r{}.zip'.format(m['version'],m['revision']) or not isinstance(m['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',m['sha256']):
        raise ValueError('invalid_package')
    if type(m['mandatory']) is not bool or type(m['requires_reconsent']) is not bool:
        raise ValueError('invalid_flags')
    for field in ('published_utc','terms_version','release_notes'):
        if not isinstance(m[field],str) or len(m[field]) > 2048 or any(ord(c)<32 and c not in '\r\n' for c in m[field]):
            raise ValueError('invalid_text')
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)',m['published_utc']):
        raise ValueError('invalid_timestamp')
    if not re.fullmatch(r'[0-9.]{0,32}',m['terms_version']):
        raise ValueError('invalid_terms')
    lines=['MNSL-UPDATE-V1']
    for field in FIELDS:
        value=m[field]
        if type(value) is bool:
            value='true' if value else 'false'
        if field=='release_notes':
            value=value.replace('\r',' ').replace('\n',' ')
        elif isinstance(value,str) and ('\r' in value or '\n' in value):
            raise ValueError('invalid_line_break')
        lines.append(field+'='+str(value))
    return '\n'.join(lines).encode('utf-8')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


def authorize(environ):
    base=environ.get('HTTP_X_SSO_NODE','')
    token=environ.get('HTTP_X_HA_SESSION','')
    if base not in NODES or len(token)>8192 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',token):
        raise PermissionError('invalid_session')
    # The selected node checks token MAC, live SSO status, current principal role and admin:manage.
    req=urllib.request.Request(base+'/ha/tenant-admin.php',headers={'Accept':'application/json','X-HA-Session':token,'User-Agent':'MNSL-SSO-Signer/1'})
    with urllib.request.build_opener(NoRedirect()).open(req,timeout=20) as response:
        raw=response.read(1048577)
        if response.status!=200 or len(raw)>1048576 or json.loads(raw.decode()).get('ok') is not True:
            raise PermissionError('admin_required')
    encoded=token.split('.')[0]
    claims=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)).decode())
    now=int(time.time())
    if claims.get('auth_source')!='oidc_sso' or claims.get('purpose')!='ha_admin' or claims.get('client')!='desktop' or 'admin:manage' not in claims.get('scope',[]) or not now<int(claims.get('expires',0))<=now+300 or not now-300<=int(claims.get('reauthenticated_at',0))<=now+60 or not re.fullmatch('[a-f0-9]{64}',str(claims.get('credential_id_hash',''))):
        raise PermissionError('fresh_admin_required')
    return base,claims['credential_id_hash']


def handle(environ,start_response,data):
    def reply(status,value):
        body=json.dumps(value,separators=(',',':')).encode()
        start_response(status,[('Content-Type','application/json'),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),('Content-Length',str(len(body)))])
        return [body]
    path=environ.get('PATH_INFO','')
    method=environ.get('REQUEST_METHOD','GET')
    try:
        if path=='/mnsl-signing/public-key' and method=='GET':
            return reply('200 OK',public_key(data))
        if path!='/mnsl-signing/sign' or method!='POST':
            return reply('405 Method Not Allowed',{'ok':False,'error':'method_not_allowed'})
        size=int(environ.get('CONTENT_LENGTH','0'))
        if not 0<size<=16384 or environ.get('CONTENT_TYPE','').split(';')[0]!='application/json':
            return reply('400 Bad Request',{'ok':False,'error':'invalid_body'})
        raw=environ['wsgi.input'].read(size)
        if len(raw)!=size:
            raise ValueError('truncated_body')
        manifest=json.loads(raw.decode('utf-8'))
        payload=canonical(manifest)
        base,principal=authorize(environ)
        public=public_key(data)
        audit=Path(data)/'mnsl-signing-audit.sqlite3'
        con=sqlite3.connect(str(audit),timeout=20)
        os.chmod(str(audit),0o600)
        try:
            con.execute('CREATE TABLE IF NOT EXISTS signatures(at INTEGER,principal TEXT,node TEXT,package TEXT,sha256 TEXT,payload_sha256 TEXT,key_id TEXT)')
            con.execute('BEGIN IMMEDIATE')
            if con.execute('SELECT COUNT(*) FROM signatures WHERE principal=? AND at>?',(principal,int(time.time())-60)).fetchone()[0]>=20:
                con.rollback()
                return reply('429 Too Many Requests',{'ok':False,'error':'signing_rate_limited'})
            sig=subprocess.run(['openssl','dgst','-sha256','-sign',str(key_path(data))],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout
            con.execute('INSERT INTO signatures VALUES(?,?,?,?,?,?,?)',(int(time.time()),principal,base,manifest['package_name'],manifest['sha256'],hashlib.sha256(payload).hexdigest(),public['key_id']))
            con.commit()
        finally:
            con.close()
        return reply('200 OK',{'ok':True,'key_id':public['key_id'],'signature':base64.b64encode(sig).decode(),'principal_hash':principal})
    except PermissionError:
        return reply('403 Forbidden',{'ok':False,'error':'administrator_sso_required'})
    except (ValueError,TypeError,KeyError):
        return reply('400 Bad Request',{'ok':False,'error':'invalid_signing_request'})
    except Exception:
        return reply('503 Service Unavailable',{'ok':False,'error':'signing_unavailable'})
