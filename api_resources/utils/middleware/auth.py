
# active_directory checks based RBAC

# GMI creds generating token, timeout
import ldap
import ldap.filter
import sys
import os
from functools import wraps
from flask import request
import jwt
if sys.version_info[0] > 2:
    from api_resources.api_constants.constants import *
    from network_iac_common_utils.authHelper import VaultNetworkIAC
else:
    from api_resources.api_constants.constants import *
    # sys.path.insert(1, '/var/www/control/Helpers')
    # from authHelper import VaultNetworkIAC


def grabPass(file=MID_PASSWORD_FILE, profile="root",
             secret_path="networkteam/network-ui-kaos/prd/appsecret-test",
             fetchkey=None):
    if os.path.exists('/.dockerenv'):
        vault_iac = VaultNetworkIAC()
        f = vault_iac.fetch_vault_secrets(secret_path=secret_path, secret_key=fetchkey)
        return f
    else:
        profiles = open(file, "r")
        rval = None
        for item in profiles:
            [user, pw] = item[:-1].split(":")
            if user == profile:
                rval = pw
                break
        profiles.close()
        return (rval)


def grabPassVault(secret_path="networkteam/network-ui-kaos/prd/appsecret-test",
                  fetchkey=None):
    '''
    apc = AppRoleClient(verify=False)
    t = apc.get_client(VAULT_APP_ROLE_ID, VAULT_SECRET_ID)
    if t.is_authenticated():
        vault = GMIVault(t)
        f = vault.get_kv_secret(secret_path,
                                secret_key=fetchkey)
        return f
    '''
    vault_iac = VaultNetworkIAC()
    f = vault_iac.fetch_vault_secrets(secret_path=secret_path, secret_key=fetchkey)
    return f


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        print(request.headers)
        token = request.headers.get('Authorization')
        if not token:
            return 'Token is missing', 401
        try:
            kwargs['decoded_jwt'] = jwt.decode(token,
                                               grabPass(profile=AUTH_SECRET,
                                                        secret_path="networkteam/network-ui-kaos/prd/secrets",
                                                        fetchkey="secret_key"), algorithms=["HS256"])
        except Exception:
            return 'Token is invalid', 401
        return f(*args, **kwargs)
    return decorated


class LDAPAuthenticateHelper:
    def __init__(self, uname, passwd, ldap_server=LDAP_SERVER, ldap_port=LDAP_PORT):
        try:
            self.uname = str(uname).encode('utf-8')
            self.passwd = str(passwd).encode('utf-8')
            assert self.passwd
            self.ldap = ldap
            self.setLdapParams(ldap_server, ldap_port)
            self.bindpw = grabPass(profile=LDAP_BIND_PROFILE,
                                   secret_path="networkteam/network-ui-kaos/prd/mids-pwds",
                                   fetchkey="m1is574")
            self.binduser = LDAP_BIND_USER
        except Exception as e:
            print("Failed object init due to "+str(e))

    def setLdapParams(self, ldap_server=LDAP_SERVER, ldap_port=LDAP_PORT):
        self.ldap_server = ldap_server
        self.ldap_port = ldap_port
        self.ldap.protocol_version = 3
        self.ldap.set_option(self.ldap.OPT_X_TLS_REQUIRE_CERT, self.ldap.OPT_X_TLS_ALLOW)
        self.ldap.set_option(self.ldap.OPT_REFERRALS, 0)
     
    def connectLdap(self):
        try:
            self.ld = self.ldap.initialize("ldaps://"+self.ldap_server+":"+self.ldap_port)
        except Exception as e:
            print("Authentication failed due to: "+str(e))

    def searchUser(self, criteria=None, attributes=None):
        result_dn = None
        if not criteria:
            cr_uname = self.uname
            if sys.version_info[0] > 2:
                cr_uname = self.uname.decode()
            criteria = '(&(objectClass=user)(sAMAccountName=' + \
                ldap.filter.escape_filter_chars(cr_uname) + \
                ')(memberof='+ldap.filter.escape_filter_chars(LDAP_MEMBER_DN) + '))'
        if not attributes:
            attributes = ['displayName']
        try:
            result = self.ld.bind_s(self.binduser, self.bindpw)
            results = self.ld.search_s(LDAP_BASE_DN, self.ldap.SCOPE_SUBTREE, criteria, attributes)
            for result in results:
                result_dn = result[0]
            self.ld.unbind()
            return result_dn
        except Exception as e:
            print("Authentication failed due to: "+str(e))

    def checkLoginPermit(self, dn, criteria=None, attributes=None):
        if not criteria:
            criteria = 'userPrincipleName={}'.format(self.uname)
        if not attributes:
            attributes = ['cn']
        try:
            result2 = self.ld.bind_s(dn, self.passwd)
            self.ld.search_s(LDAP_BASE_DN, self.ldap.SCOPE_SUBTREE, criteria, attributes)
            result2_dn=result2[0]
            assert result2_dn==97
            return result2_dn
        except Exception as e:
            print("Authentication issue for login: "+str(e))
     

    def getUserPermissions(self, searched_dn, criteria=None, attributes=None):
        if not criteria:
            criteria = "(|(&(objectClass=group)(member={})))".format(searched_dn)
        if not attributes:
            attributes = ['cn']
        # print(criteria)
        try:
            self.ld.bind_s(searched_dn, self.passwd)
            result3 = self.ld.search_s(LDAP_BASE_DN, self.ldap.SCOPE_SUBTREE, criteria, attributes)
            print(result3)
            if sys.version_info[0] > 2:
                return list(set([r[1]['cn'][0].decode() for r in result3]).intersection(set(API_PERMISSIONS)))
            return list(set([r[1]['cn'][0] for r in result3]).intersection(set(API_PERMISSIONS)))
        except Exception as e:
            print("Error occrured in getting user permissions: "+str(e))
            

class AuthorizationHelper():
    pass



