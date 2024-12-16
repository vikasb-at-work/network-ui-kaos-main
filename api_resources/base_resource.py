from flask import jsonify, request
import sys
if sys.version_info[0] > 2:
    from flask_restx import Resource
    from .utils.backend_storage.backend_storage import SQLBackendStorage
    from .utils.middleware.auth import grabPass
    from .api_constants.constants import *
    from network_iac_common_utils.sys_environment import environment
else:
    from flask_restplus import Resource
    from utils.backend_storage.backend_storage import SQLBackendStorage
    from utils.middleware.auth import grabPass
    from api_constants.constants import *
    sys.path.insert(1, '/var/www/control/Helpers')
    from sys_environment import environment


env = environment()
dbpw = grabPass(profile=DB_USER, secret_path="networkteam/network-ui-kaos/prd/db-creds",
                fetchkey="dan")
db_util = SQLBackendStorage("mysql+pymysql://"+DB_USER+":"+dbpw+"@"+env.DB+":3306"+"/"+KAOS_DB)
print(db_util)


class BaseIACResource(Resource):

    def __init__(self, *args, **kwargs):
        super(BaseIACResource, self).__init__(*args, **kwargs)

    def get(self, key_filter_arg=None):
        try:
            kw_filter = None
            if isinstance(self.iac_params, list):
                key_filter_arg = {}
                for param in self.iac_params:
                    param_value = request.args.get(param, None)
                    if param_value:
                        key_filter_arg[param] = request.args.get(param)
            else:
                key_filter_arg = request.args.get(self.iac_params)
            print(key_filter_arg)
            if not key_filter_arg:
                data = db_util.select_all(self.orm_model)
                base_schema = self.orm_schemas
                data = base_schema.dump(data)
                return data
            else:
                if not isinstance(key_filter_arg, dict):
                    filter_key = list(self.key_filter.keys())[0]
                    self.key_filter[filter_key] = key_filter_arg
                    kw_filter = self.key_filter
                else:
                    kw_filter = key_filter_arg
                data = db_util.select_all_with_filter(model_class=self.orm_model,
                                                      **kw_filter)
                # print(data)
                if len(data) > 0:
                    base_schema = self.orm_schemas
                    data = base_schema.dump(data)
                else:
                    base_schema = self.orm_schema    
                    data = base_schema.dump(data[0])
                # print(data)
                return data
        except Exception as e:
            return {'message': str("Error occured during the request: "+str(e))}, 500

    def post(self, decoded_jwt=None):
        if decoded_jwt['scope'] == "readwrite":
            try:
                data = self.iac_ns.payload
                data_obj = self.orm_model(**data)
                db_util.insert(data_obj)
                return jsonify(data)
            except Exception as e:
                return {'message': str("Error occured during the request: "+str(e))}, 500
        else:
            return "Method not allowed", 405

    def put(self, decoded_jwt=None):
        if decoded_jwt['scope'] == "readwrite":
            try:
                id = request.args.get('id')
                assert id
                # print(site)
                data = self.iac_ns.payload
                print(type(data))
                print(data)
                # gmi_core_obj = GMICore(**data)
                db_util.update(self.orm_model, data, id)
                return "Record updated successfully"
            except Exception as e:
                return {'message': str("Error occured during the request: "+str(e))}, 500
        else:
            return "Method not allowed", 405

    def delete(self, decoded_jwt=None):
        if decoded_jwt['scope'] == "readwrite":
            try:
                id = request.args.get('id')
                assert id
                db_util.delete(self.orm_model, id)
                return "Record deleted"
            except Exception as e:
                return {'message': str("Error occured during the request: "+str(e))}, 500
        else:
            return "Method not allowed", 405
