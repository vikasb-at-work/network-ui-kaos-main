import sys
if sys.version_info[0] > 2:
    from .utils.backend_storage.orm_models.switch_ds import SwitchDS, SwitchDSSchema
    from .utils.middleware.auth import token_required
    from .namespaces_models.switch_ds_ns_model import switch_ds_ns, switch_dyn_seg
    from .base_resource import BaseIACResource
else:
    from utils.backend_storage.orm_models.switch_ds import SwitchDS, SwitchDSSchema
    from utils.middleware.auth import token_required
    from namespaces_models.switch_ds_ns_model import switch_ds_ns, switch_dyn_seg
    from base_resource import BaseIACResource


@switch_ds_ns.route('/pre-config/switch-dynamic-segmentation')
class SwitchDynamicSegmentation(BaseIACResource):

    def __init__(self, *args, **kwargs):
        super(SwitchDynamicSegmentation, self).__init__(*args, **kwargs)
        self.iac_ns = switch_ds_ns
        self.iac_model = switch_dyn_seg
        self.iac_params = ['switch_name', 'site_name', 'switch_type']
        self.orm_model = SwitchDS
        self.orm_schema = SwitchDSSchema()
        self.orm_schemas = SwitchDSSchema(many=True)
        self.key_filter = {'switch_name': None, 'site_name': None, 'switch_type': None}

    @switch_ds_ns.marshal_list_with(switch_dyn_seg)
    @switch_ds_ns.doc(params={'switch_name': 'Filter by switch name',
                              'site_name': 'Filter by location',
                              'switch_type': 'Filter basis on the switch type'})
    def get(self, key_filter_arg=None):
        return super(SwitchDynamicSegmentation, self).get(key_filter_arg=key_filter_arg)

    @switch_ds_ns.doc(security='apikey')
    @token_required
    @switch_ds_ns.expect(switch_dyn_seg, validate=True)
    def post(self, decoded_jwt=None):
        return super(SwitchDynamicSegmentation, self).post(decoded_jwt=decoded_jwt)

    @switch_ds_ns.doc(security='apikey')
    @token_required
    @switch_ds_ns.doc(params={'id': 'Please provide ID to update'})
    @switch_ds_ns.expect(switch_dyn_seg, validate=False)
    def put(self, decoded_jwt=None):
        return super(SwitchDynamicSegmentation, self).put(decoded_jwt=decoded_jwt)

    @switch_ds_ns.doc(security='apikey')
    @token_required
    @switch_ds_ns.doc(params={'id': 'Please provide ID to delete'})
    def delete(self, decoded_jwt=None):
        return super(SwitchDynamicSegmentation, self).delete(decoded_jwt=decoded_jwt)