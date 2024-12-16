import sys
if sys.version_info[0] > 2:
    from .utils.backend_storage.orm_models.core_location import GMICore, GMICoreSchema
    from .utils.middleware.auth import token_required
    from .namespaces_models.sla_location_ns_model import sla_core_locations, sla_core_locations_ns
    from .base_resource import BaseIACResource
else:
    from utils.backend_storage.orm_models.core_location import GMICore, GMICoreSchema
    from utils.middleware.auth import token_required
    from namespaces_models.sla_location_ns_model import sla_core_locations, sla_core_locations_ns
    from base_resource import BaseIACResource


@sla_core_locations_ns.route('/config/sla_locations')
class SLACoreLocations(BaseIACResource):

    def __init__(self, *args, **kwargs):
        super(SLACoreLocations, self).__init__(*args, **kwargs)
        self.iac_ns = sla_core_locations_ns
        self.iac_model = sla_core_locations
        self.iac_params = 'coreSwitch'
        self.orm_model = GMICore
        self.orm_schema = GMICoreSchema()
        self.orm_schemas = GMICoreSchema(many=True)
        self.key_filter = {'core': None}

    @sla_core_locations_ns.marshal_list_with(sla_core_locations)
    @sla_core_locations_ns.doc(params={'coreSwitch': 'Filter by core switch'})
    def get(self, key_filter_arg=None):
        return super(SLACoreLocations, self).get(key_filter_arg=key_filter_arg)

    @sla_core_locations_ns.doc(security='apikey')
    @token_required
    @sla_core_locations_ns.expect(sla_core_locations, validate=True)
    def post(self, decoded_jwt=None):
        return super(SLACoreLocations, self).post(decoded_jwt=decoded_jwt)

    @sla_core_locations_ns.doc(security='apikey')
    @token_required
    @sla_core_locations_ns.doc(params={'id': 'Please provide ID to update'})
    @sla_core_locations_ns.expect(sla_core_locations, validate=False)
    def put(self, decoded_jwt=None):
        return super(SLACoreLocations, self).put(decoded_jwt=decoded_jwt)

    @sla_core_locations_ns.doc(security='apikey')
    @token_required
    @sla_core_locations_ns.doc(params={'id': 'Please provide ID to delete'})
    def delete(self, decoded_jwt=None):
        return super(SLACoreLocations, self).delete(decoded_jwt=decoded_jwt)
