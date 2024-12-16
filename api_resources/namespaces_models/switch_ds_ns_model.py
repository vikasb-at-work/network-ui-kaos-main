import sys
if sys.version_info[0] > 2:
    from flask_restx import Namespace, fields
    from api_resources.api_constants.constants import authorizations
else:
    from flask_restplus import Namespace, fields
    from api_resources.api_constants.constants import authorizations


switch_ds_ns = Namespace('switch-dynamic-segmentation', description='Switch related operations', authorizations=authorizations)

switch_dyn_seg = switch_ds_ns.model('Switch_Dyn_Seg', {
    'id': fields.String(required=False, description="ID generated"),
    'switch_name': fields.String(required=False, description='Name identifier for the switch or hostname if not configured'),
    'user_email': fields.String(required=True, description='Your email address for auditing'),
    'site_name': fields.String(required=True, description='Site Name'),
    'model': fields.String(required=False, description='Model of the switch'),
    'mgmt_ip': fields.String(required=True, description='Switch access IP address if possible with subnet mask'),
    'data_ip': fields.String(required=False, description='Switch data-band IP address if possible with subnet mask'),
    'base_config': fields.Boolean(required=True, description='If the switch site is provisioned with base_config or not'),
    'add_to_clearpass': fields.Boolean(required=True, description='If the switch site is added to the clearpass or not'),
    'controller': fields.Boolean(required=False, description='If the switch site has a controller or not'),
    'oobm': fields.Boolean(required=True, description='If the switch can be accessed via OOBM or not'),
    'admin_vlan': fields.Integer(required=False, description='Admin VLAN'),
    'voice_vlan': fields.Integer(required=False, description='Voice VLAN'),
    'p_controller_ip': fields.String(required=False, description='IP of primary controller'),
    's_controller_ip': fields.String(required=False, description='IP of secondary controller'),
    'sourced_vlan': fields.Integer(required=False, description='VLAN to be sourced from for radius interface'),
    'primary_clearpass_ip': fields.String(required=False, description="Primary clearpass IP"),
    'secondary_clearpass_ip': fields.String(required=False, description="Secondary clearpass IP"),
    'switch_type': fields.String(required=False, description='Type of the switch'),
    'auto_vlan_detection': fields.Boolean(requied=False, description='VLANs detected automatically'),
    'rfmgmt_vlan': fields.Integer(required=False, description='RF Mgmt VLAN'),
    'gmiwli_vlan': fields.Integer(required=False, description='GMIWLI Vlan'),
    'wpa_ewn_vlan': fields.Integer(required=False, description='WPA OR EWN Vlan'),
    'rf_guest_vlan': fields.Integer(required=False, description='RF Guest VLAN'),
    'status': fields.String(required=False, description="Status of the configuration")
})
