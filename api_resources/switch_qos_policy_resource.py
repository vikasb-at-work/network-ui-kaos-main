import sys
if sys.version_info[0] > 2:
    from .utils.backend_storage.orm_models.policy_qos import PolicyQOS, PolicyQOSSchema
    from .utils.middleware.auth import token_required
    from .namespaces_models.switch_qos_policy_ns_model import switch_qos_policy, \
        qos_policy_ns
    from .base_resource import BaseIACResource
else:
    from utils.backend_storage.orm_models.policy_qos import PolicyQOS, PolicyQOSSchema
    from utils.middleware.auth import token_required
    from namespaces_models.switch_qos_policy_ns_model import switch_qos_policy, \
        qos_policy_ns
    from base_resource import BaseIACResource


@qos_policy_ns.route('/config/ip/qospolicy')
class SwitchQOSPolicy(BaseIACResource):

    def __init__(self, *args, **kwargs):
        super(SwitchQOSPolicy, self).__init__(*args, **kwargs)
        self.iac_ns = qos_policy_ns
        self.iac_model = switch_qos_policy
        self.iac_params = 'id'
        self.orm_model = PolicyQOS
        self.orm_schema = PolicyQOSSchema()
        self.orm_schemas = PolicyQOSSchema(many=True)
        self.key_filter = {'id': None}

    @qos_policy_ns.marshal_list_with(switch_qos_policy)
    @qos_policy_ns.doc(params={'id': 'Filter by id'})
    def get(self, key_filter_arg=None):
        return super(SwitchQOSPolicy, self).get(key_filter_arg=key_filter_arg)

    @qos_policy_ns.doc(security='apikey')
    @token_required
    @qos_policy_ns.expect(switch_qos_policy, validate=True)
    def post(self, decoded_jwt=None):
        return super(SwitchQOSPolicy, self).post(decoded_jwt=decoded_jwt)

    @qos_policy_ns.doc(security='apikey')
    @token_required
    @qos_policy_ns.doc(params={'id': 'Please provide ID to update'})
    @qos_policy_ns.expect(switch_qos_policy, validate=False)
    def put(self, decoded_jwt=None):
        return super(SwitchQOSPolicy, self).put(decoded_jwt=decoded_jwt)

    @qos_policy_ns.doc(security='apikey')
    @token_required
    @qos_policy_ns.doc(params={'id': 'Please provide ID to delete'})
    def delete(self, decoded_jwt=None):
        return super(SwitchQOSPolicy, self).delete(decoded_jwt=decoded_jwt)
