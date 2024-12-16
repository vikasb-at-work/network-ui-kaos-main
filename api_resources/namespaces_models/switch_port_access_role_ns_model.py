import sys
if sys.version_info[0] > 2:
    from flask_restx import Namespace, fields
    from api_resources.api_constants.constants import authorizations
else:
    from flask_restplus import Namespace, fields
    from api_resources.api_constants.constants import authorizations


cx_ds_port_access_role_ns = Namespace('cx-ds-port-access-role', description='Port Acess Role for CX Dynamic Segmentation', authorizations=authorizations)

cx_ds_port_access_role = cx_ds_port_access_role_ns.model('CX_DS_Port_Access_Role', {
    'id': fields.Integer(required=False, description='ID of the record'),
    'name': fields.String(required=True, description='Name of the role'),
    'associate_policy': fields.String(required=False, description='Global role policy ["captive-portal-profile NAME", "policy NAME"] Range: Up to 64 characters'),
    'gateway_zone': fields.Integer(required=False, description='["gateway-zone zone <zone1> gateway-role <role1>"] (variable in tables/variable expansion of CP servers)'),
    'auth_mode': fields.String(required=False, description='["client-mode", "device-mode", "multi-domain"]'),
    'cached_reauth_period': fields.Integer(required=False, description='Default: 30. Range: 30 to 4294967295 '),
    'client_inactivity': fields.Integer(required=False, description='None or Default: 300. Range: 300 to 4294967295'),
    'description': fields.String(required=False, description='Specifies the role description. Up to 255 characters.'),
    'device_traffic_class': fields.String(required=False, description='["voice"] is the only option'),
    'mtu': fields.Integer(required=False, description='Specifies the MTU size in bytes of a client for a role. Range: 68 to 9198'),
    'poe_priority': fields.String(required=False, description='Default is not set, ["critical", "high", "low"]'),
    'private_vlan': fields.String(required=False, description='Default is not set, ["promiscuous","secondary"]'),
    'reauth_period': fields.Integer(required=False, description='Range: 1 to 4294967295. A reauthentication period of less than 60 seconds is not recommended.'),
    'session_timeout': fields.Integer(required=False, description='Range: 1 to 4294967295. A timeout of less than 60 seconds is not recommended.'),
    'stp_admin_edge_port': fields.Boolean(required=False, description='Default is off'),
    'trust_mode': fields.String(required=False, description='Default is not set. ["cos","dscp","none"]'),
    'vlan_access_id': fields.String(required=False, description="vlan access <1-4094>"),
    'vlan_access_name': fields.String(required=False, description='specifies the VLAN name for the access VLAN. Supports a single VLAN name. Range: Up to 32 characters.'),
    'vlan_trunk_allowed_id': fields.List(fields.Integer, required=False, description="ID of allowed vlan on Trunk"),
    'vlan_trunk_allowed_name': fields.String(required=False, description='specifies the VLAN name for the access VLAN. Supports a single VLAN name. Range: Up to 32 characters. Can have up to 50 vlan names listed'),
    'vlan_trunk_native_id': fields.String(required=False, description="vlan trunk native <1-4094>"),
    'vlan_trunk_native_name': fields.String(required=False, description='specifies the VLAN name for the access VLAN. Supports a single VLAN name. Range: Up to 32 characters.'),
    'associate_macsec_policy': fields.String(required=False, description='MACSEC policy name'),
    'associate_captive_portal_profile': fields.String(required=False, description='Captive portal profile'),
    'gateway_role': fields.String(required=False, description='Gateway role')
})
