from flask import Flask, session
from datetime import timedelta
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
import sys
import os

if sys.version_info[0] > 2:
    from flask_restx import Api
    from api_resources.api_constants.constants import *
    from api_resources.switch_ds_resource import switch_ds_ns
    from api_resources.gmi_site_resource import gmi_sites_geo_ns
    from api_resources.cp_site_profile_resource import site_profile_clearpass_ns
    from api_resources.sla_location_resource import sla_core_locations_ns
    from api_resources.switch_qos_policy_resource import qos_policy_ns
    from api_resources.auth_resource import auth_ns
    from api_resources.cx_ds_port_access_role_resource import cx_ds_port_access_role_ns
    from api_resources.switch_port_role_profile_resource import port_role_profile_ns
    from api_resources.port_access_role_gateway_zone_resource import port_access_role_gateway_zone_ns
    from api_resources.utils.backend_storage.orm_models.base_orm_model import base_ma
    from api_resources.utils.middleware.auth import grabPass
    from api_resources.utils.backend_storage.orm_models.base_orm_model import Base
    from api_resources.base_resource import db_util
    from api_resources.utils.backend_storage.orm_models import core_location, \
        cx_ds_port_access_role, policy_qos, sites_model, switch_ds, switch_port_role_profile, port_access_role_gateway_zone

else:
    from flask_restplus import Api
    from api_resources.api_constants.constants import *
    from api_resources.switch_ds_resource import switch_ds_ns
    from api_resources.gmi_site_resource import gmi_sites_geo_ns
    from api_resources.cp_site_profile_resource import site_profile_clearpass_ns
    from api_resources.switch_qos_policy_resource import qos_policy_ns
    from api_resources.sla_location_resource import sla_core_locations_ns
    from api_resources.auth_resource import auth_ns
    from api_resources.cx_ds_port_access_role_resource import cx_ds_port_access_role_ns
    from api_resources.switch_port_role_profile_resource import port_role_profile_ns
    from api_resources.port_access_role_gateway_zone_resource import port_access_role_gateway_zone_ns
    from api_resources.utils.backend_storage.orm_models.base_orm_model import base_ma
    from api_resources.utils.middleware.auth import grabPass
    from api_resources.utils.backend_storage.orm_models.base_orm_model import Base
    from api_resources.base_resource import db_util
    from api_resources.utils.backend_storage.orm_models import core_location, \
        cx_ds_port_access_role, policy_qos, sites_model, switch_ds, switch_port_role_profile, port_access_role_gateway_zone

app = Flask(__name__)

base_ma.init_app(app)

Base.metadata.create_all(db_util.engine)

api = Api(app, doc='/swagger-ui/')

api.add_namespace(switch_ds_ns, path='/v1')
api.add_namespace(auth_ns, path='/v1')
api.add_namespace(site_profile_clearpass_ns, path='/v1')
api.add_namespace(gmi_sites_geo_ns, path='/v1')
api.add_namespace(sla_core_locations_ns, path='/v1')
api.add_namespace(qos_policy_ns, path='/v1')
api.add_namespace(cx_ds_port_access_role_ns, path='/v1')
api.add_namespace(port_role_profile_ns, path='/v1')
api.add_namespace(port_access_role_gateway_zone_ns, path='/v1')

disable_warnings(InsecureRequestWarning)

if os.path.exists('/.dockerenv'):
    app.secret_key = grabPass(profile="secret_key",
                            secret_path="networkteam/network-ui-kaos/prd/secrets",
                            fetchkey="secret_key")

'''
# future docker test changes
@app.before_request
def make_session_permanent():
    if os.path.exists('/.dockerenv'):
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=15)
        session.modified = True
    else:
        pass


@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    if os.path.exists('/.dockerenv'):
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        r.headers["Pragma"] = "no-cache"
        r.headers["Expires"] = "0"
        r.headers['Cache-Control'] = 'public, max-age=0'
        return r
    else:
        pass
'''


if __name__ == '__main__':
    app.run(debug=True)
