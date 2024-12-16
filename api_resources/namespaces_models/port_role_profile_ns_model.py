import sys
if sys.version_info[0] > 2:
    from flask_restx import Namespace, fields
    from api_resources.api_constants.constants import authorizations
else:
    from flask_restplus import Namespace, fields
    from api_resources.api_constants.constants import authorizations


port_role_profile_ns = Namespace('port-role-profile', description='Port Role profile', authorizations=authorizations)

port_role_profile = port_role_profile_ns.model('Port_role_Profile', {
    'id': fields.Integer(required=False, description='ID'),
    'name': fields.String(required=True, description='Name of the profile'),
    'portaccess_ps': fields.Boolean(required=False, description='Port Access PS'),
    'portaccess_ps_mac': fields.String(required=False, description='Port access MAC'),
    'portfilter': fields.String(required=False, description='Port filter'),
    'portaccess_fb_role': fields.String(required=False, description='Port access FB role'),
    'aaa_auth_precedence': fields.Integer(required=False, description='0 no exist #1 = dot1x then mac, #2 = mac then dot1x'),
    'portaccess_ob_precedence': fields.Integer(required=False, description='0 = no exist #1=aaa then device-profile #2 = device-profile then aaa'),
    'portaccess_ob_method': fields.Integer(required=False, description='0 no exist #1=enable #2 = disable'),
    'aaa_auth_priority': fields.Integer(required=False, description='0 no exist #1=dot1x then mac_auth #2 = mac-auth then dot1x'),
    'portaccess_security_violation': fields.Integer(required=False, description='0 no exist #1 notify #2 shutdown'),
    'portaccess_security_violation_timer': fields.Integer(required=False, description='0 no exist #range 10-600'),
    'portaccess_security_violation_recovery': fields.Integer(required=False, description='0 no exist #1 enable #2 disable'),
    'critical_role': fields.String(required=False, description='Critical role details'),
    'critical_voice_role': fields.String(required=False, description='Critical voice role'),
    'preauth_role': fields.String(required=False, description='PreAuth Role'),
    'reject_role': fields.String(required=False, description='Reject role'),
    'auth_role': fields.String(required=False, description='Auth Role'),
    'auth_mode': fields.Integer(required=False, description='0 no exist #1-client-mode #2-device-mode #3=multi-domain'),
    'allow_lldp_bpdu': fields.Boolean(required=False, description='Allow LLDP BPDU'),
    'allow_cdp_bpdu': fields.Boolean(required=False, description='Allow CDP BPDU'),
    'allow_lldp_auth': fields.Boolean(required=False, description='Allow LLDP Auth'),
    'allow_cdp_auth': fields.Boolean(required=False, description='Allow CDP Auth'),
    'radius_override': fields.Integer(required=False, description='0=no exist #1 = enable #2= disable'),
    'allow_flood_traffic': fields.Integer(required=False, description='0-no exist #1 enable #2 disable'),
    'aaa_auth_mac': fields.Integer(required=False, description='0 = no exist #1 = enable #2=disable'),
    'aaa_auth_dot1x': fields.Integer(required=False, description='0 = no exist #1 =    enable #2 = disable #3 = enable/cached-reauth #4 = enable/reauth #5=enable/canned-eap-success'),
    'portaccess_device_profile': fields.Boolean(required=False, description='Port Acess Device Profile'),
    'portaccess_device_profile_mode': fields.Integer(required=False, description='0 no exist #1 block-until-profile-applied'),
    'portaccess_ps_client_limit': fields.Integer(required=False, description='0 no exist    #range 1-64'),
    'aaa_auth_client_limit': fields.Integer(required=False, description='0 no exist #range 1-256'),
    'aaa_auth_client_limit_multi': fields.Integer(required=False, description='0 no exist #range 1-5'),
    'aaa_auth_mac_quiet': fields.Integer(required=False, description='range 0-65535'),
    'aaa_auth_mac_reauth': fields.Integer(required=False, description='0 no exist #range 1-4294967295'),
    'aaa_auth_mac_reauth_period': fields.Integer(required=False, description='0 no  exist #range 30-4294967295'),
    'aaa_auth_dot1x_quiet': fields.Integer(required=False, description='range 0-65535'),
    'aaa_auth_dot1x_cached_reauth': fields.Integer(required=False, description='0 off range 30-4294967295'),
    'aaa_auth_dot1x_max_retries': fields.Integer(required=False, description='0 off range 1-10'),
    'aaa_auth_dot1x_reauth_period': fields.Integer(required=False, description='0 off range 30-4294967295'),
    'aaa_auth_dot1x_discovery_period': fields.Integer(required=False, description='range 1-65535'),
    'aaa_auth_dot1x_max_eapol': fields.Integer(required=False, description='0 off range 1-10'),
    'aaa_auth_dot1x_eapol_timeout': fields.Integer(required=False, description='range 1-65535'),
    'aaa_auth_dot1x_initial_response_timeout': fields.Integer(required=False, description='range = 1-300'),
    'description': fields.String(required=False, description='Description of the role'),
})

