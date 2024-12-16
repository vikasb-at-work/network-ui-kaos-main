import sys
if sys.version_info[0] > 2:
    from .utils.backend_storage.orm_models.sites_model import GMISites, GMISiteSchema
    from .utils.middleware.auth import token_required
    from .namespaces_models.gmi_site_ns_model import gmi_sites_geo, gmi_sites_geo_ns
    from .base_resource import BaseIACResource
else:
    from utils.backend_storage.orm_models.sites_model import GMISites, GMISiteSchema
    from utils.middleware.auth import token_required
    from namespaces_models.gmi_site_ns_model import gmi_sites_geo, gmi_sites_geo_ns
    from base_resource import BaseIACResource


@gmi_sites_geo_ns.route('/config/gmiSites')
class GMISitesGeo(BaseIACResource):

    def __init__(self, *args, **kwargs):
        super(GMISitesGeo, self).__init__(*args, **kwargs)
        self.iac_ns = gmi_sites_geo_ns
        self.iac_model = gmi_sites_geo
        self.iac_params = 'site'
        self.orm_model = GMISites
        self.orm_schema = GMISiteSchema()
        self.orm_schemas = GMISiteSchema(many=True)
        self.key_filter = {'site': None}

    @gmi_sites_geo_ns.marshal_list_with(gmi_sites_geo)
    @gmi_sites_geo_ns.doc(params={'site': 'Filter by site'})
    def get(self, key_filter_arg=None):
        return super(GMISitesGeo, self).get(key_filter_arg=key_filter_arg)

    @gmi_sites_geo_ns.doc(security='apikey')
    @token_required
    @gmi_sites_geo_ns.expect(gmi_sites_geo, validate=True)
    def post(self, decoded_jwt=None):
        return super(GMISitesGeo, self).post(decoded_jwt=decoded_jwt)

    @gmi_sites_geo_ns.doc(security='apikey')
    @token_required
    @gmi_sites_geo_ns.doc(params={'id': 'Please provide ID to update'})
    @gmi_sites_geo_ns.expect(gmi_sites_geo, validate=False)
    def put(self, decoded_jwt=None):
        return super(GMISitesGeo, self).put(decoded_jwt=decoded_jwt)

    @gmi_sites_geo_ns.doc(security='apikey')
    @token_required
    @gmi_sites_geo_ns.doc(params={'id': 'Please provide ID to delete'})
    def delete(self, decoded_jwt=None):
        return super(GMISitesGeo, self).delete(decoded_jwt=decoded_jwt)
