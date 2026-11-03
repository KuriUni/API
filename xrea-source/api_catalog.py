"""Attach OpenAPI metadata without registering or intercepting legacy URLs."""
import json
from pathlib import Path

from fastapi.openapi.utils import get_openapi


def install_catalog(api):
    def openapi():
        if api.openapi_schema is not None:
            return api.openapi_schema
        catalog = json.loads((Path(__file__).parent / 'openapi-catalog.json').read_text(encoding='utf-8'))
        schema = get_openapi(title=catalog['info']['title'], version=catalog['info']['version'],
                             description=catalog['info']['description'], routes=api.routes,
                             servers=api.servers)
        schema['paths'].update(catalog['paths'])
        for section, values in catalog.get('components', {}).items():
            schema.setdefault('components', {}).setdefault(section, {}).update(values)
        schema['tags'] = [{'name': 'health', 'description': 'FastAPIプロセスの生存確認。'}] + catalog['tags']
        schema['x-catalog-source'] = catalog['x-catalog-source']
        api.openapi_schema = schema
        return schema
    api.openapi = openapi
