"""Run the FastAPI application behind the existing Apache CGI adapter."""
import sys
import posixpath
from wsgiref.util import setup_testing_defaults

from a2wsgi import ASGIMiddleware
from asgi import app

_application = ASGIMiddleware(app)


def application(environ, start_response):
    # FastAPI's root_path is the public mount, not the rewritten CGI filename.
    environ = dict(environ)
    script = environ.get('SCRIPT_NAME', '/license/index.cgi')
    default_prefix = posixpath.dirname(script) if script.endswith('.cgi') else script
    environ["SCRIPT_NAME"] = environ.get("PYTHON_MIGRATION_URL_PREFIX", default_prefix or '/license')
    setup_testing_defaults(environ)
    environ["wsgi.errors"] = sys.stderr
    environ["wsgi.run_once"] = True
    environ["wsgi.multiprocess"] = True
    if environ.get("HTTPS", "").lower() == "on" or 'https' in environ.get("HTTP_CF_VISITOR", ""):
        environ["wsgi.url_scheme"] = "https"
    return _application(environ, start_response)
