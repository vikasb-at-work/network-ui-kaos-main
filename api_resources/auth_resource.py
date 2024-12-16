from flask import Flask, jsonify, request
import sys
if sys.version_info[0] > 2:
    from flask_restx import Namespace, Resource, Api, fields
    from .utils.middleware.auth import LDAPAuthenticateHelper
    from .utils.middleware.auth import grabPass
    from .api_constants.constants import *
else:
    from flask_restplus import Namespace, Resource, Api, fields
    from utils.middleware.auth import LDAPAuthenticateHelper
    from utils.middleware.auth import grabPass
    from api_constants.constants import *
from functools import wraps
from base64 import b64decode
import datetime
import jwt


authorizations1 = {
    'Basic Auth': {
        'type': 'basic',
        'in': 'header',
        'name': 'Authorization'
    }
}

auth_ns = Namespace('auth', description='Auth related APIs', authorizations=authorizations1)


cred_model = auth_ns.model('Creds', {
    'name':fields.String(required=True)
})



token_model = auth_ns.model('Token', {
    'token': fields.String
})



def authenticate_user(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return 'Unauthorized', 401
        auth_type, auth_string = auth_header.split(None, 1)
        # auth_string = auth_header.split()[1]
        if auth_type.lower() != 'basic':
            return 'Unsupported auth', 400
        decoded_auth_string = b64decode(auth_string)
        if sys.version_info[0] > 2:
            # decoded_auth_string = decoded_auth_string.encode('utf-8')
            uname, passwd = decoded_auth_string.decode('utf-8').split(':')
            # uname.encode('utf-8')
            # passwd.encode('utf-8')
        else:
            uname, passwd = decoded_auth_string.split(':')
        try:
            ld_obj = LDAPAuthenticateHelper(uname, passwd)
            ld_obj.connectLdap()
            dn1 = ld_obj.searchUser()
            ld_obj.setLdapParams()
            ld_obj.connectLdap()
            assert ld_obj.checkLoginPermit(dn1) == 97
            kwargs['user_name'] = uname
            kwargs['auth_user'] = dn1
            kwargs['ld_obj'] = ld_obj
        except Exception as e:
            return 'Authentication failed', 401
        return func(*args, **kwargs)
    return decorated


def get_authenticated(request):
    auth_header = request.headers.get('Authorization')
    auth_string = auth_header.split()[1]
    decoded_auth_string = b64decode(auth_string)
    uname, passwd = decoded_auth_string.split(':')
    try:
        ld_obj = LDAPAuthenticateHelper(uname, passwd)
        ld_obj.connectLdap()
        dn1 = ld_obj.searchUser()
        ld_obj.setLdapParams()
        ld_obj.connectLdap()
        assert ld_obj.checkLoginPermit(dn1) == 97
        return uname, dn1, ld_obj
    except Exception as e:
        return 'Authentication failed', 401

def fetch_user_permissions(auth_user, ld_obj):
    ld_obj.setLdapParams()
    ld_obj.connectLdap()
    auth_group = ld_obj.getUserPermissions(auth_user)
    if "NETWORK_API_ADMIN" in auth_group:
        return "readwrite"
    return "readonly"


@auth_ns.route('/auth/token')
class AuthToken(Resource):
    @auth_ns.doc(security='Basic Auth')
    @authenticate_user
    @auth_ns.expect(cred_model)
    @auth_ns.marshal_with(token_model)
    def post(self, user_name=None, auth_user=None, ld_obj=None):
        # Extract the user's credentials from the request
        # user_name, auth_user, ld_obj = get_authenticated(request)
        # return {'token': str(auth_user)}
        try:
            payload = {
                "name": user_name,
                "admin": True,
                "iat": datetime.datetime.utcnow(),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                "scope": fetch_user_permissions(auth_user, ld_obj)
            }
            encoded_token = jwt.encode(payload,
                                       grabPass(profile=AUTH_SECRET,
                                                secret_path="networkteam/network-ui-kaos/prd/secrets",
                                                fetchkey="secret_key"),
                                       algorithm='HS256')
            return {'token': encoded_token}
        except Exception as e:
            return {'message': str("Error occured during the request: "+str(e))}, 500

