import sys
if sys.version_info[0] > 2:
    from flask_restx import Namespace, fields
    from api_resources.api_constants.constants import authorizations
else:
    from flask_restplus import Namespace, fields
    from api_resources.api_constants.constants import authorizations


site_profile_clearpass_ns = Namespace('siteprofile',
                                      description='Site profile details with clearpass server details',
                                      authorizations=authorizations)

region_model_ns = Namespace('regiondata', description='Region Data', authorizations=authorizations)


gmi_sites_geo_ns = Namespace('gmisitegeo',
                             description='GMI Sites Info',
                             authorizations=authorizations)


region_model = site_profile_clearpass_ns.model('Site_Region_Data', {
    'id': fields.Integer(required=False, description='Id'),
    'name': fields.String(required=True, description='Name of the site'),
    'desc': fields.String(required=False, description='Description of the site'),
    'api_url': fields.String(required=False, description='API_URL of the site'),
    'cluster_url': fields.String(required=False, description='Cluster_URL of the site'),
    'auth_profile': fields.String(required=False, description='Auth_Profile of the site'),
    'go_url': fields.String(required=False, description='GO URL of the site') 
})


site_profile_clearpass = site_profile_clearpass_ns.model('Site_Profile_Clearpass', {
    'id': fields.Integer(required=False, description='Id'),
    'site': fields.String(required=True, description='Name of the site'),
    'region': fields.String(required=True, description='Region defined'),
    'primary_ip': fields.String(required=False, description='Primary IP of the clearpass server'),
    'secondary_ip': fields.String(required=False,
                                  description='Secondary IP of the clearpass server'),
    'cp_url': fields.String(required=False, description='ClearPass URL'),
    'controller1_ip': fields.String(required=False, description='Controller1 IP'),
    'controller2_ip': fields.String(required=False, description='Controller2 IP'),
    'region_data': fields.Nested(region_model),
    'record_type': fields.Integer(required=False, description="If site is manufacturing type")
})


gmi_sites_geo = gmi_sites_geo_ns.model('GMI_Sites_Geo', {
    'id': fields.Integer(required=False, description='Id'),
    'site': fields.String(required=True, description='Site Name'),
    'equipment': fields.String(required=True, description='Equipment details'),
    'type': fields.String(required=True, description="If site is manufacturing type"),
    'city': fields.String(required=True, description='Name of the City'),
    'state': fields.String(required=False, description="State information"),
    'country': fields.String(required=True, description='Country details'),
    'address': fields.String(required=False, description='Address details'),
    'nickname': fields.String(required=False, description='Site Nickname'),
    'region': fields.String(required=True, description='Region defined'),
    'site_override': fields.String(required=False, description='Site Override'),
    'lat': fields.Float(required=False, description='Latitude information'),
    'lng': fields.Float(required=False, description='Longitude information'),
    'postal_code': fields.String(required=False, description='Postal code'),
    'aruba_central_id':  fields.Integer(required=False, description="Aruba Central ID"),
    'address2':  fields.String(required=False, description="Additional address 2"),
    'address3':  fields.String(required=False, description="Additional address 3"),
    'attention':  fields.String(required=False, description="Attention"),
    'suffix':  fields.String(required=False, description="Suffix"),
    'region_data': fields.Nested(region_model)
})
