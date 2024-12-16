import sys
if sys.version_info[0] > 2:
    from flask_restx import Namespace, fields
    from api_resources.api_constants.constants import authorizations
else:
    from flask_restplus import Namespace, fields
    from api_resources.api_constants.constants import authorizations


qos_policy_ns = Namespace('switch-qos-policy', description='Switch QOS policy', authorizations=authorizations)

switch_qos_policy = qos_policy_ns.model('Switch_QOS_Policy', {
    'id': fields.Integer(required=False, ),
    'name': fields.String(required=True, description='Name of the policy'),
    'cos': fields.Integer(required=False, description='range 0-7'),
    'apply_policy_name': fields.String(required=False, description='Apply policy name'),
    'trust': fields.Integer(required=False, description='0 = none, 1=cos, 2=dscp'),
    'set_dscp': fields.Integer(required=False, description='range 0-63'),
    'rate_limit_type': fields.Integer(required=False, description='#0=off #1: unknown-unicast #2=broadcast #3=multicast #4=icmp'),
    'rate_limit_subtype': fields.Integer(required=False, description='#0=ip-all, #1=ipv4,#2=ipv6'),
    'rate_limit_value': fields.Integer(required=False, description='kbps or pps'),
    'rate_limit_value_type': fields.Boolean(required=False, description='False=kbps #True: PPS'), 
    'qos_shape': fields.Integer(required=False, description='0 off range 49-100000000')
})
