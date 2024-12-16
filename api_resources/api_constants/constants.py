LDAP_SERVER = "mgolbdc.genmills.com"
LDAP_PORT = "3269"
LDAP_BIND_USER = "CN=M1IS574,OU=Users,OU=MGO,OU=Sites,DC=genmills,DC=com"
LDAP_BIND_PROFILE = "m1is574"
LDAP_MEMBER_DN = "CN=SAMURAI_USERS,OU=Other Groups,OU=IS Security Groups,OU=Information Systems,DC=genmills,DC=com"
LDAP_BASE_DN = "DC=genmills,DC=com"
MID_PASSWORD_FILE = "/mnt/data1/network/data/mid_password_file.txt"
DB_USER = "dan"
#DB_SERVER = "xnetkaos1"
KAOS_DB = "kaosdb"
API_PERMISSIONS = ["NETWORK_API_ADMIN", "NETWORK_API_READONLY"]
AUTH_SECRET = "secret_key"

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}
