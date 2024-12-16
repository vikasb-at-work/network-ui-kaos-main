import sys
if sys.version_info[0] > 2:
    from .utils.backend_storage.orm_models.sites_model import SiteCPProfile, SiteCPProfileSchema
    from .utils.middleware.auth import token_required
    from .namespaces_models.gmi_site_ns_model import site_profile_clearpass, \
        site_profile_clearpass_ns
    from .base_resource import BaseIACResource
else:
    from utils.backend_storage.orm_models.sites_model import SiteCPProfile, SiteCPProfileSchema
    from utils.middleware.auth import token_required
    from namespaces_models.gmi_site_ns_model import site_profile_clearpass, \
        site_profile_clearpass_ns
    from base_resource import BaseIACResource


@site_profile_clearpass_ns.route('/config/cp/siteprofile')
class CPSiteProfile(BaseIACResource):

    def __init__(self, *args, **kwargs):
        super(CPSiteProfile, self).__init__(*args, **kwargs)
        self.iac_ns = site_profile_clearpass_ns
        self.iac_model = site_profile_clearpass
        self.iac_params = 'site'
        self.orm_model = SiteCPProfile
        self.orm_schema = SiteCPProfileSchema()
        self.orm_schemas = SiteCPProfileSchema(many=True)
        self.key_filter = {'site': None}

    @site_profile_clearpass_ns.marshal_list_with(site_profile_clearpass)
    @site_profile_clearpass_ns.doc(params={'site': 'Filter by site'})
    def get(self, key_filter_arg=None):
        return super(CPSiteProfile, self).get(key_filter_arg=key_filter_arg)

    @site_profile_clearpass_ns.doc(security='apikey')
    @token_required
    @site_profile_clearpass_ns.expect(site_profile_clearpass, validate=True)
    def post(self, decoded_jwt=None):
        return super(CPSiteProfile, self).post(decoded_jwt=decoded_jwt)

    @site_profile_clearpass_ns.doc(security='apikey')
    @token_required
    @site_profile_clearpass_ns.doc(params={'id': 'Please provide ID to update'})
    @site_profile_clearpass_ns.expect(site_profile_clearpass, validate=False)
    def put(self, decoded_jwt=None):
        return super(CPSiteProfile, self).put(decoded_jwt=decoded_jwt)

    @site_profile_clearpass_ns.doc(security='apikey')
    @token_required
    @site_profile_clearpass_ns.doc(params={'id': 'Please provide ID to delete'})
    def delete(self, decoded_jwt=None):
        return super(CPSiteProfile, self).delete(decoded_jwt=decoded_jwt)

