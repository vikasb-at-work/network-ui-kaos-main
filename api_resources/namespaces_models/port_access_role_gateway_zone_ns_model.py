import sys
if sys.version_info[0] > 2:
    from flask_restx import Namespace, fields
    from api_resources.api_constants.constants import authorizations
else:
    from flask_restplus import Namespace, fields
    from api_resources.api_constants.constants import authorizations


port_access_role_gateway_zone_ns = Namespace('port-access-role-gateway-zone', description='Port Access Role Gateway Zone', authorizations=authorizations)

port_access_role_gateway_zone = port_access_role_gateway_zone_ns.model('Port_Access_Role_Gateway_Zone',  {
    'id': fields.Integer(required=False, description='ID'),
    'zone_name': fields.String(required=True, description='Name of the zone'),
    'zone_description': fields.String(required=False, description='Description of the zone'),
    'zone_number': fields.Integer(required=False, description='1 = Enterprise, 2 = Manufacturing, 3 = Lab'),
})
