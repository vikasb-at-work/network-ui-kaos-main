import sys
if sys.version_info[0] > 2:
    from .utils.backend_storage.orm_models.cx_ds_port_access_role import CXDSPortAccessRole, CXDSPortAccessRoleSchema
    from .utils.middleware.auth import token_required
    from .namespaces_models.switch_port_access_role_ns_model import cx_ds_port_access_role_ns, cx_ds_port_access_role
    from .base_resource import BaseIACResource
    from network_iac_common_utils.switchFunctionHelper import vlans_to_bytes, vlans_from_list
else:
    from utils.backend_storage.orm_models.cx_ds_port_access_role import CXDSPortAccessRole, CXDSPortAccessRoleSchema
    from utils.middleware.auth import token_required
    from namespaces_models.switch_port_access_role_ns_model import cx_ds_port_access_role_ns, cx_ds_port_access_role
    from base_resource import BaseIACResource
    sys.path.insert(1, '/var/www/control/Helpers')
    from switchFunctionHelper import vlans_from_list, vlans_to_bytes


@cx_ds_port_access_role_ns.route('/config/ip/switch-port-access-role')
class SwitchPortAccessRole(BaseIACResource):

    def __init__(self, *args, **kwargs):
        super(SwitchPortAccessRole, self).__init__(*args, **kwargs)
        self.iac_ns = cx_ds_port_access_role_ns
        self.iac_model = cx_ds_port_access_role
        self.iac_params = 'name'
        self.orm_model = CXDSPortAccessRole
        self.orm_schema = CXDSPortAccessRoleSchema()
        self.orm_schemas = CXDSPortAccessRoleSchema(many=True)
        self.key_filter = {'name': None}

    @cx_ds_port_access_role_ns.marshal_list_with(cx_ds_port_access_role)
    @cx_ds_port_access_role_ns.doc(params={'name': 'Filter by policy name'})
    def get(self, key_filter_arg=None):
        return super(SwitchPortAccessRole, self).get(key_filter_arg=key_filter_arg)

    @cx_ds_port_access_role_ns.doc(security='apikey')
    @token_required
    @cx_ds_port_access_role_ns.expect(cx_ds_port_access_role, validate=True)
    def post(self, decoded_jwt=None):
        data = self.iac_ns.payload
        if data.get('vlan_trunk_allowed_id', None):
            data['vlan_trunk_allowed_id'] = vlans_to_bytes(vlans_from_list(data['vlan_trunk_allowed_id']))
        return super(SwitchPortAccessRole, self).post(decoded_jwt=decoded_jwt)

    @cx_ds_port_access_role_ns.doc(security='apikey')
    @token_required
    @cx_ds_port_access_role_ns.doc(params={'id': 'Please provide ID to update'})
    @cx_ds_port_access_role_ns.expect(cx_ds_port_access_role, validate=False)
    def put(self, decoded_jwt=None):
        data = self.iac_ns.payload
        if data.get('vlan_trunk_allowed_id', None):
            data['vlan_trunk_allowed_id'] = vlans_to_bytes(vlans_from_list(data['vlan_trunk_allowed_id']))
        return super(SwitchPortAccessRole, self).put(decoded_jwt=decoded_jwt)

    @cx_ds_port_access_role_ns.doc(security='apikey')
    @token_required
    @cx_ds_port_access_role_ns.doc(params={'id': 'Please provide ID to delete'})
    def delete(self, decoded_jwt=None):
        return super(SwitchPortAccessRole, self).delete(decoded_jwt=decoded_jwt)
