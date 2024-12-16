import sys
if sys.version_info[0] > 2:
    from .utils.backend_storage.orm_models.switch_port_role_profile import SwitchPortRoleProfile, SwitchPortRoleProfileSchema
    from .utils.middleware.auth import token_required
    from .namespaces_models.port_role_profile_ns_model import port_role_profile_ns, port_role_profile
    from .base_resource import BaseIACResource
else:
    from utils.backend_storage.orm_models.switch_port_role_profile import SwitchPortRoleProfile, SwitchPortRoleProfileSchema
    from utils.middleware.auth import token_required
    from namespaces_models.port_role_profile_ns_model import port_role_profile_ns, port_role_profile
    from base_resource import BaseIACResource


@port_role_profile_ns.route('/config/ip/switch-port-role-profile')
class CXSwitchPortRoleProfile(BaseIACResource):

    def __init__(self, *args, **kwargs):
        super(CXSwitchPortRoleProfile, self).__init__(*args, **kwargs)
        self.iac_ns = port_role_profile_ns
        self.iac_model = port_role_profile
        self.iac_params = 'name'
        self.orm_model = SwitchPortRoleProfile
        self.orm_schema = SwitchPortRoleProfileSchema()
        self.orm_schemas = SwitchPortRoleProfileSchema(many=True)
        self.key_filter = {'name': None}

    @port_role_profile_ns.marshal_list_with(port_role_profile)
    @port_role_profile_ns.doc(params={'name': 'Filter by policy name'})
    def get(self, key_filter_arg=None):
        return super(CXSwitchPortRoleProfile, self).get(key_filter_arg=key_filter_arg)

    @port_role_profile_ns.doc(security='apikey')
    @token_required
    @port_role_profile_ns.expect(port_role_profile, validate=True)
    def post(self, decoded_jwt=None):
        return super(CXSwitchPortRoleProfile, self).post(decoded_jwt=decoded_jwt)

    @port_role_profile_ns.doc(security='apikey')
    @token_required
    @port_role_profile_ns.doc(params={'id': 'Please provide ID to update'})
    @port_role_profile_ns.expect(port_role_profile, validate=False)
    def put(self, decoded_jwt=None):
        return super(CXSwitchPortRoleProfile, self).put(decoded_jwt=decoded_jwt)

    @port_role_profile_ns.doc(security='apikey')
    @token_required
    @port_role_profile_ns.doc(params={'id': 'Please provide ID to delete'})
    def delete(self, decoded_jwt=None):
        return super(CXSwitchPortRoleProfile, self).delete(decoded_jwt=decoded_jwt)
