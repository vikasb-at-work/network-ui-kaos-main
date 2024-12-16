import sys
if sys.version_info[0] > 2:
    from flask_restx import Namespace, fields
    from api_resources.api_constants.constants import authorizations
else:
    from flask_restplus import Namespace, fields
    from api_resources.api_constants.constants import authorizations


sla_core_locations_ns = Namespace('SLA-core-locations', description='SLA Core locations', authorizations=authorizations)

sla_core_locations = sla_core_locations_ns.model('SLA_Core_Locations', {
    'id': fields.Integer(required=False, description="Record ID"),
    'core': fields.String(required=False, description='Core switch defined'),
    'description': fields.String(required=True, description='Description of the core location'),
    'asNum': fields.String(required=True, description='AS Number')
})
