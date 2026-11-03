"""URL mount shared by isolated validation and production deployments."""
import os
import re
import json
from pathlib import Path

TEST_PREFIX='/license/python-migration'

def url_prefix():
    value=os.environ.get('PYTHON_MIGRATION_URL_PREFIX',TEST_PREFIX).rstrip('/')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+',value) or '..' in value.split('/') or '//' in value:
        raise RuntimeError('invalid_deployment_url_prefix')
    return value

def site_url(value):
    return value.replace(TEST_PREFIX,url_prefix())

def load_deployment_config():
    """Load an allowlisted private profile before any handler is imported."""
    profile=os.environ.get('PYTHON_MIGRATION_PROFILE','test')
    if profile not in {'test','production'}:raise RuntimeError('invalid_deployment_profile')
    raw=os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR','')
    path=Path(raw)/'deployment-config.json' if raw else None
    value={}
    if path is not None and path.is_file():
        if path.is_symlink() or path.stat().st_size>16384:raise RuntimeError('unsafe_deployment_config')
        value=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value,dict):raise RuntimeError('invalid_deployment_config')
    role=value.get('ha_role',os.environ.get('PYTHON_MIGRATION_HA_ROLE',''))
    if profile=='production' and role not in {'primary','standby'}:
        raise RuntimeError('production_ha_role_required')
    if role:
        if role not in {'primary','standby'}:raise RuntimeError('invalid_ha_role')
        os.environ['PYTHON_MIGRATION_HA_ROLE']=role
    else:
        os.environ.setdefault('PYTHON_MIGRATION_HA_ROLE','primary')
    if profile=='production':os.environ.setdefault('PYTHON_MIGRATION_URL_PREFIX','/license')
    url_prefix()
    if 'ha_peer' in value:
        from urllib.parse import urlsplit
        peer=str(value['ha_peer']).rstrip('/')
        parsed=urlsplit(peer)
        if peer and (parsed.scheme!='https' or parsed.hostname not in {'2415.jp','backup.2415.jp','main.2415.jp'}
                     or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise RuntimeError('invalid_ha_peer')
        os.environ['PYTHON_MIGRATION_HA_PEER']=peer
    if profile=='production' and value.get('enable_production_writes') is True:
        os.environ['PYTHON_MIGRATION_ENABLE_PRODUCTION_WRITES']='1'
    if 'mail' in value:
        mail=value['mail']
        if not isinstance(mail,dict) or mail.get('transport') not in {'smtp','sendmail'}:
            raise RuntimeError('invalid_mail_transport')
        if mail['transport']=='sendmail' and profile!='production':
            raise RuntimeError('sendmail_requires_production_profile')
        fields={'transport':'MAIL_TRANSPORT','from':'MAIL_FROM','sendmail_path':'SENDMAIL_PATH',
                'smtp_host':'SMTP_HOST','smtp_port':'SMTP_PORT','smtp_user':'SMTP_USER',
                'smtp_ssl':'SMTP_SSL','smtp_starttls':'SMTP_STARTTLS','timeout':'SMTP_TIMEOUT'}
        for key,suffix in fields.items():
            if key not in mail:continue
            item=mail[key]
            if not isinstance(item,(str,int,bool)) or isinstance(item,str) and ('\r' in item or '\n' in item):
                raise RuntimeError('invalid_mail_setting')
            os.environ['PYTHON_MIGRATION_'+suffix]=str(int(item)) if isinstance(item,bool) else str(item)
