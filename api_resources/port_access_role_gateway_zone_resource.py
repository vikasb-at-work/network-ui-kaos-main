import sys
if sys.version_info[0] > 2:
    from .utils.backend_storage.orm_models.port_access_role_gateway_zone import PortAccessRoleGatewayZone, PortAccessRoleGatewayZoneSchema
    from .utils.middleware.auth import token_required
    from .namespaces_models.port_access_role_gateway_zone_ns_model import port_access_role_gateway_zone_ns, port_access_role_gateway_zone
    from .base_resource import BaseIACResource
else:
    from utils.backend_storage.orm_models.port_access_role_gateway_zone import PortAccessRoleGatewayZone, PortAccessRoleGatewayZoneSchema
    from utils.middleware.auth import token_required
    from namespaces_models.port_access_role_gateway_zone_ns_model import port_access_role_gateway_zone_ns, port_access_role_gateway_zone
    from base_resource import BaseIACResource


@port_access_role_gateway_zone_ns.route('/config/ip/port-access-role-gateway-zone')
class CXDSPortAccessRoleGatewayZone(BaseIACResource):

    def __init__(self, *args, **kwargs):
        super(CXDSPortAccessRoleGatewayZone, self).__init__(*args, **kwargs)
        self.iac_ns = port_access_role_gateway_zone_ns
        self.iac_model = port_access_role_gateway_zone
        self.iac_params = 'zone_name'
        self.orm_model = PortAccessRoleGatewayZone
        self.orm_schema = PortAccessRoleGatewayZoneSchema()
        self.orm_schemas = PortAccessRoleGatewayZoneSchema(many=True)
        self.key_filter = {'zone_name': None}

    @port_access_role_gateway_zone_ns.marshal_list_with(port_access_role_gateway_zone)
    @port_access_role_gateway_zone_ns.doc(params={'zone_name': 'Filter by zone name'})
    def get(self, key_filter_arg=None):
        return super(CXDSPortAccessRoleGatewayZone, self).get(key_filter_arg=key_filter_arg)

    @port_access_role_gateway_zone_ns.doc(security='apikey')
    @token_required
    @port_access_role_gateway_zone_ns.expect(port_access_role_gateway_zone, validate=True)
    def post(self, decoded_jwt=None):
        return super(CXDSPortAccessRoleGatewayZone, self).post(decoded_jwt=decoded_jwt)

    @port_access_role_gateway_zone_ns.doc(security='apikey')
    @token_required
    @port_access_role_gateway_zone_ns.doc(params={'id': 'Please provide ID to update'})
    @port_access_role_gateway_zone_ns.expect(port_access_role_gateway_zone, validate=False)
    def put(self, decoded_jwt=None):
        return super(CXDSPortAccessRoleGatewayZone, self).put(decoded_jwt=decoded_jwt)

    @port_access_role_gateway_zone_ns.doc(security='apikey')
    @token_required
    @port_access_role_gateway_zone_ns.doc(params={'id': 'Please provide ID to delete'})
    def delete(self, decoded_jwt=None):
        return super(CXDSPortAccessRoleGatewayZone, self).delete(decoded_jwt=decoded_jwt)
    
