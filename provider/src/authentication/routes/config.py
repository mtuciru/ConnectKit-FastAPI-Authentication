from oauth2lib.endpoints import configure_endpoints, MetadataFieldsObject, ConfigureOptionsObject, EndpointsObject
from ..oauth.validator import request_validator

_endpoints: EndpointsObject = None


def init_oauth2lib_endpoints(metadata_fields: MetadataFieldsObject, options: ConfigureOptionsObject):
    global _endpoints
    _endpoints = configure_endpoints(request_validator, metadata_fields, options)


def get_endpoints():
    global _endpoints
    return _endpoints
