import sys
from flask import Flask, request, render_template, flash, redirect, session, app, current_app, Response, send_from_directory
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
import jwt
import ldap
import ldap.filter
import re
import socket
import requests
#from flask_ldap_login.forms import LDAPLoginForm
#from flask_ldap_login import LDAP3LoginManager, AuthenticationResponse
#from py2neo import Graph
#from f5.bigip import ManagementRoot
import os
if os.path.exists('/.dockerenv'):
    sys.path.append("/var/tmp/utilHelpers")
from collections import OrderedDict
from urllib.parse import urlencode, parse_qs, urljoin, urlparse
from network_iac_common_utils.arubaCXHelper import ArubaCX
from network_iac_common_utils.arubaHelper import ArubaOS
from network_iac_common_utils.authHelper import Auth
from network_iac_common_utils.authHelper import VaultNetworkIAC
from sqlalchemy import Nullable, inspect, desc, asc
from healthcheck import HealthCheck
import os
if os.path.exists('/.dockerenv'):
    from network_iac_common_utils.sqlHelper import sql
    from network_iac_common_utils.sys_environment import environment
else:
    sys.path.append("./Helpers")
    from Helpers.sys_environment import environment
    from Helpers.sqlHelper import sql
import json
import requests
from datetime import timedelta, datetime
from sqlalchemy import func, Index
from sqlalchemy.orm import aliased
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify
from flask_marshmallow import Marshmallow
from flask_cors import CORS, cross_origin
import datetime
from collections import Counter
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
import io
import pandas as pd
import logging
import logging.handlers
import mod_wsgi
from zoneinfo import ZoneInfo

grafana_server = "mgomtgrafanap1.genmills.com"
grafana_port = 3000

syslog = logging.getLogger(__name__)
syslog.setLevel(logging.INFO)
formatter = logging.Formatter(fmt="KAOS/CONTROL %(asctime)s %(name)s %(message)s", datefmt='%Y/%m/%d %H:%M:%S')
if not os.path.exists('/.dockerenv'):
    remote_syslog = logging.handlers.SysLogHandler(address=('172.16.219.225',514))
    remote_syslog.setFormatter(formatter)
    syslog.addHandler(remote_syslog)

disable_warnings(InsecureRequestWarning)

app = Flask(__name__)
if not os.path.exists('/.dockerenv'):
    env = environment(override=mod_wsgi.process_group)
else:
    env = environment()

# testing if changes are reflected

'''
VAULT_SECRET_ID = os.getenv("VAULT_SECRET_ID")
VAULT_APP_ROLE_ID = os.getenv("VAULT_APP_ROLE_ID")
'''

#TODO -- SWITCH THIS FOR VAULT --MAYBE MAKE AUTHHELPER SUPPORT VAULT
def grabPass(file="/etc/network/data/mid_password_file.txt",profile="root"):
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


if os.path.exists('/.dockerenv'):
    syslog.info("Inside the docker environment")
    dbpw = grabPassVault(secret_path="networkteam/network-ui-kaos/prd/db-creds",
                         fetchkey="dan")
    ADMIN_PASS = grabPassVault(secret_path="networkteam/network-ui-kaos/prd/secrets",
                               fetchkey="admin")
    TEST_PASS = grabPassVault(secret_path="networkteam/network-ui-kaos/prd/secrets",
                              fetchkey="Secret1")
    # syslog.info(env.DB)
    # syslog.info("Test credentials obtained"+str(TEST_PASS))
    # syslog.info("Going for creating a new sql object")
    s = sql(dbPassword=dbpw)
    # syslog.info("DB-User:"+str(s.dbUser))
    # syslog.info("DB-Host:"+str(s.dbHost))
    # syslog.info("DB-Port:"+str(s.dbPort))
    # syslog.info("Database:"+str(s.db))
else:
    dbpw = grabPass("/etc/network/data/mid_password_file.txt","dan")
    ADMIN_PASS = grabPass("/etc/network/data/mid_password_file.txt","admin")

if sys.version_info[0] > 2:
    if os.path.exists('/.dockerenv') and "genmills.com" not in env.DB:
        env.DB = env.DB+".genmills.com"
    # syslog.info(env.DB)
    syslog.info("Creating DB URI with sql-alchemy")
    app.config['SQLALCHEMY_DATABASE_URI'] ="mysql+pymysql://{}:{}@{}:3306/kaosdb".format("dan",dbpw, env.DB)
else:
    app.config['SQLALCHEMY_DATABASE_URI'] ="mysql://{}:{}@{}/kaosdb".format("dan", dbpw, env.DB)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['DEBUG'] = True

sdb = SQLAlchemy(app)
ma = Marshmallow(app)

# some global functions
def get_auth():
    auth = {}
    session_keys = session.keys()
    if "authSwitches" in session_keys:
        auth["session"] = session["authSwitches"]
        if session["authSwitches"]:
            auth["switches"] = True
        else:
            auth["switches"] = False
    else:
        auth["switches"] = False
    if "name" in session_keys:
        auth["authenticated_user"] = session["name"]
    if "_user_id" in session_keys:
        auth["user_id"] = session["_user_id"].decode('utf-8')
    auth["env"] = env.Name
    auth["host_version"] = sys.version_info[0]
    auth["backend_host"] = API_SWAGGER_HOST
    #set user api token
    auth["api_token"] = session.get("token", None)
    if not os.path.exists('/.dockerenv'):
        print(env.Name, env.DB, mod_wsgi.process_group)
        auth["dockerenv"] = ""
    else:
        auth["dockerenv"] = "dockerenv"
    return (auth)


class TokenStorage:
    def __init__(self):
        self.token = None

    def set_token(self, value):
        self.token = value

    def get_token(self):
        return self.token
    
strToken = TokenStorage()


def vlans_from_list(vlans=[]):
    all_vlans = [0 for v in range(0,4095)]
    for v in vlans:
        all_vlans[v]=1
    return "".join(str(v) for v in all_vlans)

def vlans_to_list(vlans=""):
    l=[]
    for i in range(0,len(vlans)):
        if int(vlans[i])==1:
            l.append(int(i))
    return (l)

def vlans_to_bytes(vlans):
    #chunk long binary string full of 12-bit values into 8-bit values to store as byte string in db
    if sys.version_info[0] > 2:
        result=bytearray()
        for i in range(0, len(vlans), 8):
            result.append(int(vlans[i:i+8],2))
        return(result)
    else:
        result=b""
        for i in range(0, len(vlans), 8):
            result=result+chr(int(vlans[i:i+8],2))
        return(result)

def vlans_from_bytes(vlans):
    #convert bytes back to bits into binary string
    result=""
    for byte in vlans:
        if sys.version_info[0] > 2:
            result=result+"{0:08b}".format(byte)
        else:
            result=result+"{0:08b}".format(ord(byte))
    return(result)

def lag_from_list(lags=[]):
    all_lags = [0 for v in range(0,256)]
    for l in lags:
        all_lags[l]=1
    return "".join(str(l) for l in all_lags)

def lag_to_list(lags=""):
    l=[]
    for i in range(0,len(lags)):
        if int(lags[i])==1:
            l.append(int(i))
    return (l)

def lag_to_bytes(lags):
    #chunk long binary string full of 12-bit values into 8-bit values to store as byte string in db
    if sys.version_info[0] > 2:
        result=bytearray()
        for i in range(0, len(lags), 8):
            result.append(int(lags[i:i+8],2))
        return(result)
    else:
        result=b""
        for i in range(0, len(lags), 8):
            result=result+chr(int(lags[i:i+8],2))
        return(result)

def lag_from_bytes(vlans):
    #convert bytes back to bits into binary string
    result=""
    for byte in vlans:
        if sys.version_info[0] > 2:
            result=result+"{0:08b}".format(byte)
        else:
            result=result+"{0:08b}".format(ord(byte))
    return(result)

def mirror_from_bytes(B):
    result=""
    for byte in B:
        if sys.version_info[0] > 2:
            result=result+"{0:08b}".format(byte)
        else: 
            result=result+"{0:08b}".format(ord(byte))
    return(result)

def mirror_from_list(l=[]):
    all_ports = [0 for i in range(0,640)]
    for p in l:
        if "/" in p:
            data = p.split("/")
            port=int(data[2])
        elif ":" in p:
            data = p.split(":")
            port=int(data[1])
        switch=int(data[0])
        all_ports[(switch-1)*64+port-1]=1
    return "".join(str(p) for p in all_ports)

def mirror_to_bytes(b):
    if sys.version_info[0] > 2:
        result=bytearray()
        for i in range(0, len(b), 8):
            result.append(int(b[i:i+8],2))
        return(result)
    else:
        result=b""
        for i in range(0, len(b), 8):
            result=result+chr(int(b[i:i+8],2))
        return(result)

def mirror_to_list(b=""):
    l=[]
    for i in range(0,len(b)):
        if int(b[i])==1:
            switch=i//64+1
            port=i%64+1
            l.append("{}/1/{}".format(switch,port))
    return (l)

def rxtx_from_bytes(B):
    result=""
    for byte in B:
        if sys.version_info[0] > 2:
            result=result+"{0:08b}".format(byte)
        else:
            result=result+"{0:08b}".format(ord(byte))
    return(result)

def rxtx_from_list(l=[],size=640):
    all_ports = ["00" for i in range(0,size)]
    for p in l:
        all_ports[p[0]-1]="{0:02b}".format((int(p[1])), 'b')
    return "".join(str(p) for p in all_ports)

def rxtx_to_bytes(b):
    if sys.version_info[0] > 2:
        result=bytearray()
        for i in range(0, len(b), 8):
            result.append(int(b[i:i+8],2))
        return(result)
    else:
        result=b""
        for i in range(0, len(b), 8):
            result=result+chr(int(b[i:i+8],2))
        return(result)

def rxtx_to_list(b, size=640):
    l=[]
    for i in range(0,len(b),2):
        if (b[i:i+2] != '00'):
            l.append([(i//2)+1,int(b[i:i+2],2)])
    return (l)

def stack_to_bigint(stack_list=[]):
    result = 0
    x = 0
    for i in range (0,64):
        if x==0:
            x=1
        else:
            x = x * 2
        if i in stack_list:
            result = result | x
    return (result)

def stack_from_bigint(stack_int):
    result = []
    x = 0
    for i in range (0,64):
        if x==0:
            x=1
        else:
            x = x * 2
        if stack_int & x:
            result.append(i)
    return (result)

# end some global functions

class BASE (sdb.Model):
    __abstract__ = True
    def to_dict(self):
        return {field.name:getattr(self, field.name) for field in self.__table__.c}

class SamuraiMaster(sdb.Model):
    __tablename__ = 'samurai_master'
    __table_args__ = (
        Index('samurai_master_serials', 'serialNumber', 'parentSN'),
    )
    id = sdb.Column(sdb.BIGINT, primary_key=True)
    source = sdb.Column(sdb.INTEGER)
    name = sdb.Column(sdb.String(255), unique=True)
    lastUpdate = sdb.Column(sdb.TIMESTAMP, nullable=False, server_default=func.current_timestamp(), onupdate=func.current_timestamp())
    samuraiYear = sdb.Column(sdb.INTEGER)
    location = sdb.Column(sdb.INTEGER)
    serialNumber = sdb.Column(sdb.String(128), index=True)
    parentSN = sdb.Column(sdb.String(128), index=True)
    IP = sdb.Column(sdb.String(40))
    mac = sdb.Column(sdb.String(24), index=True)
    budgetSource = sdb.Column(sdb.INTEGER)
    samuraiMonth = sdb.Column(sdb.INTEGER)
    version = sdb.Column(sdb.String(64))
    capital = sdb.Column(sdb.INTEGER)
    expSaas = sdb.Column(sdb.INTEGER)
    expMaint = sdb.Column(sdb.INTEGER)
    expOther = sdb.Column(sdb.INTEGER)
    comment = sdb.Column(sdb.String(255))
    vendor = sdb.Column(sdb.INTEGER)
    po = sdb.Column(sdb.String(32))
    pgo = sdb.Column(sdb.String(32))
    installDate = sdb.Column(sdb.Date)
    costCenter = sdb.Column(sdb.String(12))
    taxFacility = sdb.Column(sdb.String(32))
    baseValue = sdb.Column(sdb.INTEGER)
    loeHours = sdb.Column(sdb.INTEGER)
    model = sdb.Column(sdb.BIGINT)
    planner = sdb.Column(sdb.INTEGER, default=1)
    newModel = sdb.Column(sdb.BIGINT)
    newCapital = sdb.Column(sdb.INTEGER)
    state = sdb.Column(sdb.INTEGER)
    lastSeen = sdb.Column(sdb.DateTime)
    firstSeen = sdb.Column(sdb.DateTime)

class SamuraiMasterSchema(ma.Schema):
    class Meta:
        fields = ('id', 'source', 'name', 'lastUpdate', 'samuraiYear',
                'location', 'serialNumber', 'parentSN', 'IP', 'mac',
                'budgetSource', 'samuraiMonth', 'version', 'capital', 'expSaas',
                'expMaint', 'expOther', 'comment', 'vendor', 'po', 'pgo',
                'installDate', 'costCenter', 'taxFacility', 'baseValue',
                'loeHours', 'model', 'planner', 'newModel', 'newCapital',
                'state', 'lastSeen', 'firstSeen')

class SamuraiDeviceTypes(sdb.Model):
    __tablename__ = 'samurai_devicetypes'

    id = sdb.Column(sdb.Integer, primary_key=True)
    deviceType = sdb.Column(sdb.String(255), nullable=True)

class SamuraiDeviceTypesSchema(ma.Schema):
    class Meta:
        fields = ('id', 'deviceType')

class SamuraiVendors(sdb.Model):
    __tablename__ = 'samurai_vendors'

    id = sdb.Column(sdb.Integer, primary_key=True)
    vendor = sdb.Column(sdb.String(32), nullable=True)

class SamuraiVendorsSchema(ma.Schema):
    class Meta:
        fields = ('id', 'vendor')

class SamuraiSites(sdb.Model):
    __tablename__ = 'samurai_sites'

    id = sdb.Column(sdb.Integer, primary_key=True)
    location = sdb.Column(sdb.String(255), nullable=True)  #This is the site name (e.g. "MGO" or "CNQK")
    remap_id = sdb.Column(sdb.Integer, nullable=True)
    region = sdb.Column(sdb.Integer, nullable=False, server_default='1')
    state = sdb.Column(sdb.Integer, nullable=False, server_default='0')
    lat = sdb.Column(sdb.Float, nullable=True)
    lng = sdb.Column(sdb.Float, nullable=True)

class SamuraiSitesSchema(ma.Schema):
    class Meta:
        fields = ('id', 'location', 'remap_id', 'region', 'state', 'lat', 'lng')

class SamuraiRegions(sdb.Model):
    __tablename__ = 'samurai_regions'

    id = sdb.Column(sdb.Integer, primary_key=True)
    name = sdb.Column(sdb.String(32), nullable=True) #Text name of the region
    description = sdb.Column(sdb.String(255), nullable=True) #Description of the region
    factor = sdb.Column(sdb.Float, nullable=True) #Factor to multiply the cost of a device by to get the cost in this region

class SamuraiRegionsSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'description', 'factor')

class ChangeAuditLog(sdb.Model):
    __tablename__ = 'change_audit_log'

    id = sdb.Column(sdb.Integer, primary_key=True)
    resource_id = sdb.Column(sdb.Integer, nullable=False)
    team = sdb.Column(sdb.String(255), nullable=False, comment='Currently just network and platform')
    submitted_by = sdb.Column(sdb.String(255), nullable=False, comment='GID of the user that creates the log entry')
    created_time = sdb.Column(sdb.DateTime, nullable=False)
    team_group = sdb.Column(sdb.String(255), nullable=False, comment='IaC, SDWan, Switch, etc...')
    site = sdb.Column(sdb.String(255), default='', nullable=True)
    change_log = sdb.Column(sdb.Text, nullable=False)
    affected_systems = sdb.Column(sdb.String(255), default='', nullable=True)
    environment = sdb.Column(sdb.Integer, nullable=False, comment='0 = PROD, 1 = NON-PROD')
    crq = sdb.Column(sdb.String(255), default='', nullable=True)
    modified = sdb.Column(sdb.Integer, default=0, index=True, nullable=False, comment='0 = no, 1 = yes')
    original_id = sdb.Column(sdb.Integer, default=None, index=True, comment='If this row is the result of a modification this colomn references the original row ID')
    modified_by = sdb.Column(sdb.String(255), default='', nullable=True)
    modified_time = sdb.Column(sdb.DateTime, default=None, nullable=True)
    modification_reason = sdb.Column(sdb.String(255), default='', nullable=True)
    archived = sdb.Column(sdb.Integer, default=0, index=True, nullable=True, comment='0 = no, 1 = yes')
    archived_by = sdb.Column(sdb.String(255), default='', nullable=True)
    archived_reason = sdb.Column(sdb.String(255), default='', nullable=True)
    archived_time = sdb.Column(sdb.DateTime, default=None, nullable=True)

class ChangeAuditLogSchema(ma.Schema):
    class Meta:
        fields = ('id', 'resource_id', 'team', 'submitted_by', 'created_time', 'team_group', 'site',
				  'change_log', 'affected_systems', 'environment', 'crq', 'modified', 'original_id', 'modified_by', 
				  'modified_time', 'modification_reason', 'archived', 'archived_by', 'archived_reason', 'archived_time')

class SamuraiProducts(sdb.Model):
    __tablename__ = 'samurai_products'

    id = sdb.Column(sdb.Integer, primary_key=True)
    product = sdb.Column(sdb.String(255), index=True)
    capital = sdb.Column(sdb.Integer, nullable=True)
    expOther = sdb.Column(sdb.Integer, nullable=True)
    expSaas = sdb.Column(sdb.Integer, nullable=True)
    expMaint = sdb.Column(sdb.Integer, nullable=True)
    current = sdb.Column(sdb.Boolean, default=True)
    deviceType = sdb.Column(sdb.Integer, default=1)
    vendor = sdb.Column(sdb.Integer, default=1)
    productType = sdb.Column(sdb.Integer, default=1)
    end_of_sale = sdb.Column(sdb.Date, nullable=True)
    end_of_hw_renew = sdb.Column(sdb.Date, nullable=True)
    end_of_sw_sec_upd = sdb.Column(sdb.Date, nullable=True)
    end_of_hw_support = sdb.Column(sdb.Date, nullable=True)
    end_of_support = sdb.Column(sdb.Date, nullable=True)
    announcement = sdb.Column(sdb.String(255), default="")
    productAlias = sdb.Column(sdb.String(255), default="")
    modelNumber = sdb.Column(sdb.String(255), default="")
    productLink = sdb.Column(sdb.String(255), default="")
    productNotes = sdb.Column(sdb.Text, default="")
    maint1PartNumber = sdb.Column(sdb.String(255), default="")
    maint1Description = sdb.Column(sdb.String(255), default="")
    maint2PartNumber = sdb.Column(sdb.String(255), default="")
    maint2Description = sdb.Column(sdb.String(255), default="")
    discovered = sdb.Column(sdb.Integer, default=0)

class SamuraiProductsSchema(ma.Schema):
    class Meta:
        fields = ('id', 'product', 'capital', 'expOther', 'expSaas', 'expMaint', 'current', 'deviceType',
                  'vendor', 'productType', 'end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd',
                  'end_of_hw_support', 'end_of_support', 'announcement', 'productAlias', 'modelNumber', 
                  'productLink', 'productNotes', 'maint1PartNumber', 'maint2PartNumber', 
                  'maint1Description', 'maint2Description', 'discovered') 

class SamuraiReplacements(sdb.Model):
    __tablename__ = 'samurai_replacements'

    id = sdb.Column(sdb.INTEGER, primary_key=True)
    productOld = sdb.Column(sdb.BIGINT)
    productNew = sdb.Column(sdb.BIGINT)

class SamuraiReplacementsSchema(ma.Schema):
    class Meta:
        fields = ('id', 'productOld', 'productNew')

class DNSServer(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    ip_addr = sdb.Column(sdb.String(256))
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
class DNSServerSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'ip_addr' )

class NTPServer(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    ip_address = sdb.Column(sdb.String(256))
    def __init__(self, ip_address):
        self.ip_address = ip_address
class NTPServerSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'ip_address' )

class switch_models(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    model = sdb.Column(sdb.String(64), sdb.ForeignKey("site_switches.model"), nullable=False, index=True, unique=True)
    description = sdb.Column(sdb.String(256), nullable=False)
    copper = sdb.Column(sdb.Integer)
    sfp = sdb.Column(sdb.Integer)
    sfp_plus = sdb.Column(sdb.Integer)
    sfp_28 = sdb.Column(sdb.Integer)
    sfp_56 = sdb.Column(sdb.Integer)
    family = sdb.Column(sdb.String(10), default="6200", nullable=False)
    display = sdb.Column(sdb.Boolean, default=False)
    slot_limit = sdb.Column(sdb.String(255), default="0")
    qsfp_40_100 = sdb.Column(sdb.Integer, default=0)
    def __init__(self, model, description, copper, sfp, sfp_plus, sfp_28,
            sfp_56, family, display, slot_limit="0", qsfp_40_100=0):
        self.model = model
        self.description = description
        self.copper=copper
        self.sfp=sfp
        self.sfp_plus=sfp_plus
        self.sfp_28=sfp_28
        self.sfp_56=sfp_56
        self.family=family
        self.display=display
        self.slot_limit=slot_limit
        self.qsfp_40_100=qsfp_40_100
class switch_modelsSchema(ma.Schema):
    class Meta:
        fields = ('id', 'model', 'description', 'copper', 'sfp', 'sfp_plus',
                'sfp_28', 'sfp_56', 'family', 'display', 'slot_limit',
                'qsfp_40_100')

class site_switches(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    site = sdb.Column(sdb.String(24), nullable=False, index=True)
    model = sdb.Column(sdb.String(64), sdb.ForeignKey("switch_models.model"), nullable=False, index=True)
    switch_name = sdb.Column(sdb.String(128), nullable=False, index=True)
    switch_number = sdb.Column(sdb.Integer)
    type = sdb.Column(sdb.Integer)
    serial = sdb.Column(sdb.String(128), nullable=False, index=True)
    MAC = sdb.Column(sdb.String(128), nullable=False, index=True)
    portTypes = sdb.Column(sdb.String(256), nullable=False, default="0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0")
    stack_link1 = sdb.Column(sdb.BigInteger, default=0)
    stack_link2 = sdb.Column(sdb.BigInteger, default=0)
    __table_args__=(sdb.Index('site_switches_index', "site", "switch_name", "switch_number", unique=True),)
    family = sdb.relationship('switch_models',
            foreign_keys='site_switches.model', viewonly=True)
    def __init__(self, site, model, switch_name, serial, MAC, switch_number=1,type=2,
            portTypes="0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0",stack_link1=0,stack_link2=0,family='6200'):
        self.site = site
        self.model = model
        self.switch_name = switch_name
        self.switch_number = switch_number
        self.type = type
        self.serial = serial
        self.MAC = MAC
        self.portTypes = portTypes
        self.stack_link1 = stack_link1
        self.stack_link2 = stack_link2
        self.family = family
    def serialize(self):
        return {"id":self.id,
                "site":self.site,
                "model":self.model,
                "switch_name":self.switch_name,
                "switch_number":self.switch_number,
                "serial":self.serial,
                "type":self.type,
                "MAC":self.MAC,
                "portTypes":self.portTypes,
                "stack_link1":self.stack_link1,
                "stack_link2":self.stack_link2,
                "family":self.family.family}
class site_switchesSchema(ma.Schema):
    family = ma.Nested(switch_modelsSchema)
    class Meta:
        fields = ('id', 'site', 'model', 'switch_name', 'serial', 'MAC',
                'switch_number', 'type', 'portTypes', 'stack_link1',
                'stack_link2', 'family')

class sla_locations(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    core = sdb.Column(sdb.String(64))
    description = sdb.Column(sdb.String(128))
    asNum = sdb.Column(sdb.Integer)
    def __init__(self, core, description, asNum):
        self.core = core
        self.description=description
        self.asNum = asNum
class sla_locationsSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'core', 'description', 'asNum')

class switch_multi_vars(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    name = sdb.Column(sdb.String(128), index=True, unique=True)
    description = sdb.Column(sdb.String(128))
    value = sdb.Column(sdb.Text)
    def __init__(self, name, description, value):
        self.name = name
        self.description = description
        self.value = value
class switch_multi_varsSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'name', 'description', 'value' )

class switch_site_multi_vars(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    site = sdb.Column(sdb.String(24), nullable=False)
    name = sdb.Column(sdb.String(128), nullable=False)
    description = sdb.Column(sdb.String(128))
    value = sdb.Column(sdb.Text)
    __table_args__=(sdb.Index('ix_switch_site_multi_vars_site_name', "site", "name", unique=True),)
    def __init__(self, site, name, description, value):
        self.name = name
        self.site = site
        self.description = description
        self.value = value
class switch_site_multi_varsSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'site', 'name', 'description', 'value' )

class switch_device_multi_vars(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), nullable=False)
    name = sdb.Column(sdb.String(128), nullable=False)
    description = sdb.Column(sdb.String(128))
    value = sdb.Column(sdb.Text)
    __table_args__=(sdb.Index('switch_device_multi_vars_index', "switch_name", "name", unique=True),)
    def __init__(self, switch_name, name, description, value):
        self.name = name
        self.switch_name = switch_name
        self.description = description
        self.value = value
class switch_device_multi_varsSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'switch_name', 'name', 'description', 'value' )

class global_vlans(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    vlan = sdb.Column(sdb.Integer, index=True, unique=True)
    name = sdb.Column(sdb.String(256))
    def __init__(self, vlan, name):
        self.name = name
        self.vlan = vlan
class global_vlansSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'name', 'vlan' )

class site_vlans(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    site = sdb.Column(sdb.String(24), index=True, nullable=False)
    vlan = sdb.Column(sdb.Integer, index=True, nullable=False)
    name = sdb.Column(sdb.String(256))
    type = sdb.Column(sdb.Integer, nullable=False)
    shutdown = sdb.Column(sdb.Boolean)
    voice = sdb.Column(sdb.Boolean)
    igmp = sdb.Column(sdb.Integer)
    dhcp_snooping = sdb.Column(sdb.Boolean)
    client_tracking = sdb.Column(sdb.Boolean)
    acl_in_ip = sdb.Column(sdb.String(128))
    acl_out_ip = sdb.Column(sdb.String(128))
    acl_in_mac = sdb.Column(sdb.String(128))
    acl_out_mac = sdb.Column(sdb.String(128))
    __table_args__=(sdb.Index('site_vlans_index', "site", "vlan", "type", unique=True),)
    def __init__(self, site, vlan, name, vlan_type=1, shutdown=0, voice=0, igmp=1,
            dhcp_snooping=1, client_tracking=0, acl_in_ip="", acl_out_ip="",
            acl_in_mac="", acl_out_mac=""):
        self.site = site
        self.vlan = vlan
        self.name = name
        self.type = vlan_type
        self.shutdown = shutdown
        self.voice = voice
        self.igmp = igmp
        self.acl_in_mac=acl_in_mac
        self.acl_out_mac=acl_out_mac
        self.acl_in_ip=acl_in_ip
        self.acl_out_ip=acl_out_ip
        self.client_tracking=client_tracking
        self.dhcp_snooping=dhcp_snooping
class site_vlansSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'site', 'vlan', 'name', 'type', 'shutdown', 'voice', 'igmp',
        'dhcp_snooping', 'client_tracking', 'acl_in_mac', 'acl_out_mac', 'acl_in_ip', 'acl_out_ip' )

class cp_region(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    name = sdb.Column(sdb.String(32), nullable=False)
    desc = sdb.Column(sdb.String(256))
    api_url = sdb.Column(sdb.String(128))
    cluster_url = sdb.Column(sdb.String(128))
    auth_profile = sdb.Column(sdb.String(128))
    go_url = sdb.Column(sdb.String(128))
    primary_ip = sdb.Column(sdb.String(64), nullable=True)
    secondary_ip = sdb.Column(sdb.String(64), nullable=True)
    tertiary_ip = sdb.Column(sdb.String(64), nullable=True)
    primary = sdb.Column(sdb.String(64), nullable=True)
    secondary = sdb.Column(sdb.String(64), nullable=True)
    tertiary = sdb.Column(sdb.String(64), nullable=True)
    hub_code = sdb.Column(sdb.String(12), nullable=True)
    def __init__(self, name, desc, api_url, cluster_url, auth_profile, go_url,
            primary_ip, secondary_ip, tertiary_ip, primary, secondary, tertiary, hub_code):
        self.name=name
        self.desc=desc
        self.api_url=api_url
        self.cluster_url=cluster_url
        self.auth_profile=auth_profile
        self.go_url=go_url
        self.primary_ip=primary_ip
        self.secondary_ip=secondary_ip
        self.tertiary_ip=tertiary_ip
        self.primary=primary
        self.secondary=secondary
        self.tertiary=tertiary
        self.hub_code=hub_code
class cp_regionSchema(ma.Schema):
    class Meta:
        fields=('id','name','desc', 'api_url', 'cluster_url', 'auth_profile',
        'go_url', 'primary_ip', 'secondary_ip', 'tertiary_ip', 'primary', 'secondary', 'tertiary', 'hub_code')

class cp_site_profile(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    site = sdb.Column(sdb.String(32), index=True, nullable=False)
    region = sdb.Column(sdb.Integer, sdb.ForeignKey("cp_region.id"), nullable=False, default=1)
    primary_ip = sdb.Column(sdb.String(64))
    secondary_ip = sdb.Column(sdb.String(64))
    cp_url = sdb.Column(sdb.String(128))
    controller1_ip = sdb.Column(sdb.String(64))
    controller2_ip = sdb.Column(sdb.String(64))
    record_type = sdb.Column(sdb.SmallInteger, default=1)
    __table_args__=(sdb.Index('cp_region_site_index', "region", "site", "record_type", unique=True),)
    regionData = sdb.relationship('cp_region', foreign_keys='cp_site_profile.region')
    def __init__(self, site, region, primary_ip, secondary_ip, cp_url,
            controller1_ip, controller2_ip, record_type):
        self.site = site.upper()
        self.region = region
        self.primary_ip = primary_ip
        self.secondary_ip = secondary_ip
        self.cp_url = cp_url
        self.controller1_ip = controller1_ip
        self.controller2_ip = controller2_ip
        self.record_type = record_type
class cp_site_profileSchema(ma.Schema):
    class Meta:
        model = cp_site_profile
        fields=('id','site','region','primary_ip','secondary_ip','cp_url',
        'controller1_ip', 'controller2_ip', 'regionData', 'record_type')
    regionData = ma.Nested(cp_regionSchema)
        
class switch_device_vlans(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128),  nullable=False, index=True)
    vlan = sdb.Column(sdb.Integer, sdb.ForeignKey("site_vlans.vlan"), index=True, nullable=False)
    site = sdb.Column(sdb.String(24), sdb.ForeignKey("site_vlans.site"), index=True, nullable=False)
    __table_args__=(sdb.Index('switch_device_vlans_index', "switch_name", "vlan", unique=True),)
    def __init__(self, switch_name, site, vlan):
        self.switch_name = switch_name
        self.vlan = vlan
        self.site = site
class switch_device_vlansSchema(ma.Schema):
    class Meta:
        fields = ( 'id', 'switch_name', 'site', 'vlan')

class gmi_sites(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    site = sdb.Column(sdb.String(24), nullable=False, index=True, unique=True)
    type = sdb.Column(sdb.String(32), nullable=False)
    equipment = sdb.Column(sdb.String(8), nullable=False, default='0')
    address = sdb.Column(sdb.String(256))
    city = sdb.Column(sdb.String(64), nullable=False)
    state = sdb.Column(sdb.String(64), nullable=False)
    country = sdb.Column(sdb.String(64), nullable=False)
    nickname = sdb.Column(sdb.String(256), nullable=False)
    site_override = sdb.Column(sdb.String(24), nullable=True)
    dhcp_override = sdb.Column(sdb.String(24), nullable=True)
    lat = sdb.Column(sdb.Float, nullable=True)
    lng = sdb.Column(sdb.Float, nullable=True)
    postal_code = sdb.Column(sdb.String(16), nullable=True)
    aruba_central_id = sdb.Column(sdb.Integer, nullable=True)
    address2 = sdb.Column(sdb.String(256), nullable=True)
    address3 = sdb.Column(sdb.String(256), nullable=True)
    suffix = sdb.Column(sdb.String(256), nullable=True)
    attention = sdb.Column(sdb.String(256), nullable=True)
    active = sdb.Column(sdb.Integer, default=1)
    region = sdb.Column(sdb.Integer, sdb.ForeignKey("cp_region.id"), nullable=False, default=1)
    regionData = sdb.relationship('cp_region', foreign_keys="gmi_sites.region")
    def __init__(self, site, type, address, city, state, country, nickname,
            region, equipment=0, site_override='', dhcp_override='', lat='', lng='',
            postal_code='',
            aruba_central_id='', address2='', address3='', suffix='',attention='', active=1):
        self.site = site
        self.type = type
        self.address=address
        self.city = city
        self.state=state
        self.country=country
        self.nickname=nickname
        self.region=region
        self.equipment=equipment
        self.site_override=site_override
        self.dhcp_override=dhcp_override
        self.lat=lat
        self.lng=lng
        self.postal_code=postal_code
        self.aruba_central_id=aruba_central_id
        self.address2=address2
        self.address3=address3
        self.suffix=suffix
        self.attention=attention
        self.active=active
class gmi_sitesSchema(ma.Schema):
    class Meta:
        model = gmi_sites
        fields = ('id', 'site', 'type', 'address', 'city', 'state', 'country',
                'nickname', 'region', 'regionData', 'equipment',
                'site_override', 'dhcp_override', 'lat', 'lng', 'postal_code',
                'aruba_central_id', 'address2', 'address3', 'suffix',
                'attention', 'active')
    regionData = ma.Nested(cp_regionSchema)

class switch_ipv4_addresses(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), index=True, nullable=False)
    vlan = sdb.Column(sdb.Integer, index=True, nullable=False)
    ip_addr = sdb.Column(sdb.String(128), index=True, nullable=False)
    addr_type = sdb.Column(sdb.Integer, index=True, nullable=False, default=1)
    #1 = primary IP, #2 = secondary IP, #3 = helper addr, #4 = bootp addr,
            #5=forward protocol, #6 = static IPv4 arp
    ip_addr_extra = sdb.Column(sdb.String(128), nullable=False, default="")
    #1 = mask, #2 = mask, #3= vrf, #4 = nothing, #5 = UDP protocol, #6= MAC
    __table_args__=(sdb.Index('ix_switch_ipv4_addresses_index',
        "switch_name","vlan", "addr_type", "ip_addr",unique=True),)
    def __init__(self, switch_name, vlan, ip_addr, addr_type, ip_addr_extra):
        self.switch_name=switch_name
        self.vlan=vlan
        self.ip_addr=ip_addr
        self.addr_type=addr_type
        self.ip_addr_extra=ip_addr_extra
class switch_ipv4_addressesSchema(ma.Schema):
    class Meta:
        fields = ('id', 'switch_name', 'vlan', 'ip_addr', 'addr_type', 'ip_addr_extra')

class switch_port_role_profile(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    name = sdb.Column(sdb.String(128), nullable=False, unique=True, default="")
    portaccess_ps = sdb.Column(sdb.Boolean, default=False)
    portaccess_ps_mac = sdb.Column(sdb.String(32), default="")
    portfilter = sdb.Column(sdb.String(128), default="")
    portaccess_fb_role = sdb.Column(sdb.String(256), default="")
    aaa_auth_precedence = sdb.Column(sdb.Integer, default=0) #0 no exist #1 = dot1x then mac, #2 = mac then dot1x
    portaccess_ob_precedence = sdb.Column(sdb.Integer, default=0) #0 = no exist #1=aaa then device-profile #2 = device-profile then aaa
    portaccess_ob_method = sdb.Column(sdb.Integer, default=0) #0 no exist #1=enable #2 = disable
    aaa_auth_priority = sdb.Column(sdb.Integer, default=0) #0 no exist #1=dot1x then mac_auth #2 = mac-auth then dot1x
    portaccess_security_violation = sdb.Column(sdb.Integer, default=0) #0 no exist #1 notify #2 shutdown
    portaccess_security_violation_timer = sdb.Column(sdb.Integer, default=0) #0 no exist #range 10-600
    portaccess_security_violation_recovery = sdb.Column(sdb.Integer, default=0) #0 no exist #1 enable #2 disable
    critical_role = sdb.Column(sdb.String(128), default="")
    critical_voice_role = sdb.Column(sdb.String(128), default="")
    preauth_role = sdb.Column(sdb.String(128), default="")
    reject_role = sdb.Column(sdb.String(128), default="")
    auth_role = sdb.Column(sdb.String(128), default="")
    auth_mode = sdb.Column(sdb.Integer, default=0) #0 no exist #1-client-mode #2-device-mode #3=multi-domain
    allow_lldp_bpdu = sdb.Column(sdb.Boolean, default=False)
    allow_cdp_bpdu = sdb.Column(sdb.Boolean, default=False)
    allow_lldp_auth = sdb.Column(sdb.Boolean, default=False)
    allow_cdp_auth = sdb.Column(sdb.Boolean, default=False)
    radius_override = sdb.Column(sdb.Integer, default=0) #0=no exist #1 = enable #2= disable
    allow_flood_traffic = sdb.Column(sdb.Integer, default=0) #0-no exist #1 enable #2 disable
    aaa_auth_mac = sdb.Column(sdb.Integer, default=0) #0 = no exist #1 = enable #2=disable
    aaa_auth_mac_cached_reauth = sdb.Column(sdb.Boolean, default=False)
    aaa_auth_dot1x = sdb.Column(sdb.Integer, default=0) #0 = no exist #1 =    enable #2 = disable #3 = enable/cached-reauth #4 = enable/reauth    #5=enable/canned-eap-success
    portaccess_device_profile = sdb.Column(sdb.Boolean, default=False)
    portaccess_device_profile_mode = sdb.Column(sdb.Integer, default=0) #0 no exist #1 block-until-profile-applied
    portaccess_ps_client_limit = sdb.Column(sdb.Integer, default=0) #0 no exist    #range 1-64
    aaa_auth_client_limit = sdb.Column(sdb.Integer, default=0) #0 no exist #range 1-256
    aaa_auth_client_limit_multi = sdb.Column(sdb.Integer, default=0) #0 no exist #range 1-5
    aaa_auth_mac_quiet = sdb.Column(sdb.Integer, default=0) #range 0-65535
    aaa_auth_mac_reauth = sdb.Column(sdb.BigInteger, default=0) #0 no exist #range 1-4294967295
    aaa_auth_mac_reauth_period = sdb.Column(sdb.BigInteger, default=0) #0 no  exist #range 30-4294967295
    aaa_auth_dot1x_quiet = sdb.Column(sdb.Integer, default=0) #range 0-65535
    aaa_auth_dot1x_cached_reauth = sdb.Column(sdb.BigInteger, default=0) #0 off range 30-4294967295
    aaa_auth_dot1x_max_retries = sdb.Column(sdb.Integer, default=0) #0 off range 1-10
    aaa_auth_dot1x_reauth_period = sdb.Column(sdb.BigInteger, default=0) #0 off range 30-4294967295
    aaa_auth_dot1x_discovery_period = sdb.Column(sdb.Integer, default=0) #range 1-65535
    aaa_auth_dot1x_max_eapol = sdb.Column(sdb.Integer, default=0) #0 off range 1-10
    aaa_auth_dot1x_eapol_timeout = sdb.Column(sdb.Integer, default=0) #range 1-65535
    aaa_auth_dot1x_initial_response_timeout = sdb.Column(sdb.Integer, default=0) #range = 1-300
    def __init__(self, name, portaccess_ps, portaccess_ps_mac, portfilter,
            portaccess_fb_role, aaa_auth_precedence, portaccess_ob_precedence,
            portaccesS_ob_method, aaa_auth_priority,
            portaccess_security_violation, portaccess_security_violation_timer,
            portaccess_security_violation_recovery, critical_role,
            critical_voice_role, preauth_role, reject_role, auth_role,
            auth_mode, allow_lldp_bpdu, allow_cdp_bpdu, allow_lldp_auth,
            allow_cdp_auth, radio_override, allow_flood_traffic, aaa_auth_mac,
            aaa_auth_mac_reauth, aaa_auth_mac_cached_reauth,
            portaccess_device_profile, portaccess_device_profile_mode,
            portaccess_ps_client_limit, aaa_auth_client_limit,
            aaa_auth_client_limit_multi, aaa_auth_mac_quiet,
            aaa_auth_mac_reauth_period,
            aaa_auth_dot1x_quiet, aaa_auth_dot1x_cached_reauth,
            aaa_auth_dot1x_max_retries, aaa_auth_dot1x_reauth_period,
            aaa_auth_dot1x_discovery_period, aaa_auth_dot1x_max_eapol,
            aaa_auth_dot1x_eapol_timeout,
            aaa_auth_dot1x_initial_response_timeout):
        self.id=id
        self.portaccess_ps = portacess_ps
        self.name = name
        self.portaccess_ps_mac = portaccess_ps_mac
        self.portfilter = portfilter
        self.portaccess_fb_role = portaccess_fb_role
        self.aaa_auth_precedence = aaa_auth_precedence
        self.portaccess_ob_precedence = portaccess_ob_precedence
        self.portaccess_ob_method = portaccess_ob_method
        self.aaa_auth_priority = aaa_auth_priority
        self.portaccess_security_violation = portaccess_security_violation
        self.portaccess_security_violation_timer = portaccess_security_violation_timer
        self.portaccess_security_violation_recovery = portaccess_security_violation_recovery
        self.critical_role = critical_role
        self.critical_voice_role = critical_voice_role
        self.preauth_role = preauth_role
        self.reject_role = reject_role
        self.auth_role = auth_role
        self.auth_mode = auth_mode
        self.allow_lldp_bpdu = allow_lldp_bpdu
        self.allow_cdp_bpdu = allow_cdp_bpdu
        self.allow_lldp_auth = allow_lldp_auth
        self.allow_cdp_auth = allow_cdp_auth
        self.radius_override = radius_override
        self.allow_flood_traffic = allow_flood_traffic
        self.aaa_auth_mac = aaa_auth_mac
        self.aaa_auth_mac_reauth = aaa_auth_mac_reauth
        self.aaa_auth_mac_cached_reauth = aaa_auth_mac_cached_reauth
        self.portaccess_device_profile = portaccess_device_profile
        self.portaccess_device_profile_mode = portaccess_device_profile_mode
        self.portaccess_ps_client_limit = portaccess_ps_client_limit
        self.aaa_auth_client_limit = aaa_auth_client_limit
        self.aaa_auth_client_limit_multi = aaa_auth_client_limit_multi
        self.aaa_auth_mac_quiet = aaa_auth_mac_quiet
        self.aaa_auth_mac_reauth_period = aaa_auth_mac_reauth_period
        self.aaa_auth_dot1x_quiet = aaa_auth_dot1x_quiet
        self.aaa_auth_dot1x_cached_reauth = aaa_auth_dot1x_cached_reauth
        self.aaa_auth_dot1x_max_retries = aaa_auth_dot1x_max_retries
        self.aaa_auth_dot1x_reauth_period = aaa_auth_dot1x_reauth_period
        self.aaa_auth_dot1x_discovery_period = aaa_auth_dot1x_discovery_period
        self.aaa_auth_dot1x_max_eapol = aaa_auth_dot1x_max_eapol
        self.aaa_auth_dot1x_eapol_timeout = aaa_auth_dot1x_eapol_timeout
        self.aaa_auth_dot1x_initial_response_timeout = aaa_auth_dot1x_initial_response_timeout
class switch_port_role_profileSchema(ma.Schema):
    class Meta:
        fields = ('id','name',' portaccess_ps',' portaccess_ps_mac',' portfilter','portaccess_fb_role',' aaa_auth_precedence',' portaccess_ob_precedence','portaccesS_ob_method',' aaa_auth_priority','portaccess_security_violation',' portaccess_security_violation_timer','portaccess_security_violation_recovery',' critical_role','critical_voice_role',' preauth_role',' reject_role',' auth_role','auth_mode',' allow_lldp_bpdu',' allow_cdp_bpdu','allow_lldp_auth','allow_cdp_auth',' radio_override',' allow_flood_traffic','aaa_auth_mac','aaa_auth_mac_cached_reauth','portaccess_device_profile',' portaccess_device_profile_mode','portaccess_ps_client_limit',' aaa_auth_client_limit','aaa_auth_client_limit_multi','aaa_auth_mac_quiet','aaa_auth_mac_reauth','aaa_auth_mac_reauth_period','aaa_auth_dot1x_quiet',' aaa_auth_dot1x_cached_reauth','aaa_auth_dot1x_max_retries',' aaa_auth_dot1x_reauth_period','aaa_auth_dot1x_discovery_period',' aaa_auth_dot1x_max_eapol','aaa_auth_dot1x_eapol_timeout','aaa_auth_dot1x_initial_response_timeout')
 
class switch_port_policy(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_port_policy_name = sdb.Column(sdb.String(256), default="", nullable=False, unique=True)
    policy_in = sdb.Column(sdb.String(128), default="")
    policy_out = sdb.Column(sdb.String(128), default="")
    def __init__(self, switch_port_policy_name):
        self.switch_port_policy_name = switch_port_policy_name
class switch_port_policySchema(ma.Schema):
    class Meta:
        fields = ('id', 'switch_port_policy_name')

class switch_igmp_policy(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_igmp_policy_name = sdb.Column(sdb.String(256), default="", nullable=False, unique=True)
    version = sdb.Column(sdb.Integer, default=2, nullable=False)
    strict = sdb.Column(sdb.Boolean, default=False)
    querier = sdb.Column(sdb.Integer, default=30) # 0 = off, range 5-300
    robustness = sdb.Column(sdb.Integer, default=0) #0 =off, range 1-7
    last_member_query_interval = sdb.Column(sdb.Integer, default=0) #0=off,range 1-2
    query_max_response_time = sdb.Column(sdb.Integer, default=0) #0=off,range10-128
    static_group = sdb.Column(sdb.String(128), default="")
    access_list = sdb.Column(sdb.String(128), default="")
    router_alert_check = sdb.Column(sdb.Boolean, default=False)
    snooping_forward_vlan = sdb.Column(sdb.LargeBinary(512), default=vlans_to_bytes(vlans_from_list()))
    snooping_blocked_vlan = sdb.Column(sdb.LargeBinary(512), default=vlans_to_bytes(vlans_from_list()))
    snooping_auto_vlan = sdb.Column(sdb.LargeBinary(512), default=vlans_to_bytes(vlans_from_list()))
    snooping_fastleave_vlan = sdb.Column(sdb.LargeBinary(512), default=vlans_to_bytes(vlans_from_list()))
    snooping_forced_fastleave_vlan = sdb.Column(sdb.LargeBinary(512), default=vlans_to_bytes(vlans_from_list()))
    def __init__(self, switch_igmp_policy_name, version, strict, querier, robustness, last_member_query_interval, query_max_response_time, static_group, access_list, router_alert_check, snooping_forward_vlan, snooping_blocked_vlan, snooping_auto_vlan, snooping_fastleave_vlan, snooping_frced_fastleave_vlan):
        self.id=id
        self.switch_igmp_policy_name=switch_igmp_policy_name
        self.version = version
        self.strict = strict
        self.querier = querier
        self.robustness=robustness
        self.last_member_query_interval = last_member_query_interval
        self.query_max_response_time = query_max_response_time
        self.static_group = static_group
        self.access_list = access_list
        self.router_alert_check = router_alert_check
        self.snooping_forward_vlan = snooping_forward_vlan
        self.snooping_blocked_vlan = snooping_blocked_vlan
        self.snooping_auto_vlan = snooping_auto_vlan
        self.snooping_fastleave_vlan = snooping_fastleave_vlan
        self.snooping_forced_fastleave_vlan = snooping_forced_fastleave_vlan
class switch_igmp_policySchema(ma.Schema):
    class Meta:
        fields = ('id', 'switch_igmp_policy_name', 'version', 'strict',
        'querier', 'robustness', 'last_member_query_interval',
        'query_max_response_time', 'static_group', 'access_list',
        'router_alert_check', 'snooping_forward_vlan', 'snooping_blocked_vlan',
        'snooping_auto_vlan', 'snooping_fastleave_vlan',
        'snooping_forced_fastleave_vlan')

class switch_acl_policy(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_acl_policy_name = sdb.Column(sdb.String(256), nullable=False)
    acl_in_ip = sdb.Column(sdb.String(128), default="")
    acl_out_ip = sdb.Column(sdb.String(128), default="")
    acl_in_mac = sdb.Column(sdb.String(128), default="")
    acl_out_mac = sdb.Column(sdb.String(128), default="")
    def __init__(self, switch_acl_policy_name, acl_in_ip, acl_out_ip,
            acl_in_mac, acl_out_mac):
        self.switch_acl_policy_name=switch_acl_policy_name
        self.acl_in_ip = acl_in_ip
        self.acl_out_ip = acl_out_ip
        self.acl_in_mac = acl_in_mac
        self.acl_out_mac = acl_out_mac
class switch_acl_policySchema(ma.Schema):
    class Meta:
        fields = ('id', 'switch_acl_policy_name', 'acl_in_ip', 'acl_out_ip',
        'acl_in_mac', 'acl_out_mac')

class switch_lldp_policy(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    name = sdb.Column(sdb.String(128), default="", nullable=False)
    transmit = sdb.Column(sdb.Boolean, default=False)
    receive = sdb.Column(sdb.Boolean, default=False)
    trap_enable = sdb.Column(sdb.Boolean, default=False)
    dot3_macphy = sdb.Column(sdb.Boolean, default=False)
    dot3_poe = sdb.Column(sdb.Boolean, default=False)
    med_poe = sdb.Column(sdb.Boolean, default=False)
    med_poe_priority_override = sdb.Column(sdb.Boolean, default=False)
    med = sdb.Column(sdb.Integer, default=0) #0 not here #1 capability #2 network-policy
    med_location_civ_addr = sdb.Column(sdb.String(32), default="")
    med_location_civ_switch = sdb.Column(sdb.Integer, default=0)
    med_location_civ_desc = sdb.Column(sdb.String(128), default="")
    med_location_elin = sdb.Column(sdb.String(128), default="")
    cdp_mode = sdb.Column(sdb.Integer,default=0) #0=off #1=enabled #2=pre tx/rx
    #3=pre rx #4=pre disable
    def __init__(self, name, transmit, receive, trap_enable, dot3_macphy, dot3_poe,
            med_poe, med_poe_priority_override, med, med_location_vic_addr,
            med_location_civ_switch, med_location_civ_desc, med_location_elin,
            cdp_mode):
        self.name = name
        self.transmit=transmit
        self.receive = receive
        self.trap_enable = trap_enable
        self.dot3_macphy = dot3_macphy
        self.dot3_poe = dot3_poe
        self.med_poe = med_poe
        self.med_poe_priority_override = med_poe_priority_override
        self.med_location_civ_addr = med_location_civ_addr
        self.med_location_civ_switch = med_location_civ_switch
        self.med_location_civ_desc = med_location_civ_desc
        self.med_location_elin = med_location_elin
        self.cdp_mode = cdp_mode
class switch_lldp_policySchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'transmit', 'receive', 'trap_enable', 'dot3_macphy',
                'dot3_poe', 'med_poe', 'med_poe_priority_override', 'med',
                'med_location_civ_addr', 'med_location_civ_switch',
                'med_location_civ_desc', 'med_location_elin', 'cdp_mode')

class switch_spantree_policy(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    name = sdb.Column(sdb.String(256), nullable=False, default="", unique=True)
    spantree = sdb.Column(sdb.Integer, default=0)
    #00000001 = bpdu-guard 1
    #00000010 = root-guard 2
    #00000100 = loop-guard 4
    #00001000 = bpdu-filter 8
    #00010000 = rpvst-filter 16
    #00100000 = rpvst-guard 32
    spantree_cost = sdb.Column(sdb.Integer, default=0) #range 0-200000000
    spantree_port_priority = sdb.Column(sdb.Integer, default=0) #0-15
    spantree_port_type = sdb.Column(sdb.Integer, default=0) #0=none,
    #1=admin-edge, #2=admin-network
    spantree_link_type = sdb.Column(sdb.Integer, default=0) #0=none,
    #1=point-to-point, #2=shared
    spantree_tcn_guard = sdb.Column(sdb.Boolean, default=False)
    def __init__(self, name, spantree, spantree_cost, spantree_port_priority,
            spantree_port_type, spantree_link_type, spantree_tcn_guard):
        self.name = name
        self.spantree=spantree
        self.spantree_cost = spantree_cost
        self.spantree_port_priority=spantree_port_priority
        self.spantree_port_type = spantree_port_type
        self.spantree_link_type = spantree_link_type
        self.spantree_tcn_guard = spantree_tcn_guard
class switch_spantree_policySchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'spantree', 'spantree_cost',
        'spantree_port_priority', 'spantree_port_type', 'spantree_link_type',
        'spantree_tcn_guard')

class switch_qos_policy(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    name = sdb.Column(sdb.String(256), nullable=False, default="", unique=True)
    cos = sdb.Column(sdb.Integer, default=0) #range 0-7
    apply_policy_name = sdb.Column(sdb.String(128), default="")
    trust = sdb.Column(sdb.Integer, default=0) #0 = none, 1=cos, 2=dscp
    set_dscp = sdb.Column(sdb.Integer, default=0) #range 0-63
    rate_limit_type = sdb.Column(sdb.Integer, default=0) #0=off #1 = unknown-unicast
    #2=broadcast #3=multicast #4=icmp
    rate_limit_subtype = sdb.Column(sdb.Integer, default=0) #0=ip-all, #1=ipv4,#2=ipv6
    rate_limit_value = sdb.Column(sdb.Integer, default=0) #kbps or pps
    rate_limit_value_type = sdb.Column(sdb.Boolean, default=False) #False=kbps #True = PPS
    qos_shape = sdb.Column(sdb.Integer, default=0) #0 off #range 49-100000000
    def __init__(self, name, cos, apply_policy_name, trust, set_dscp,
            rate_limit_type, rate_limit_subtype, rate_limit_value,
            rate_limit_value_type, qos_shape):
        self.name = name
        self.cos = cos
        self.apply_policy_name = apply_policy_name
        self.trust = trust
        self.set_dscp = set_dscp
        self.rate_limit_type = rate_limit_type
        self.rate_limit_subtype = rate_limit_subtype
        self.rate_limit_value = rate_limit_value
        self.rate_limit_value_type = rate_limit_value_type
        self.qos_shape = qos_shape
class switch_qos_policySchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'cos', 'apply_policy_name', 'trust', 'set_dscp',
                'rate_limit_type', 'rate_limit_subtype', 'rate_limit_value',
                'rate_limit_value_type', 'qos_shape')

class switch_trunk_lag(BASE):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), index=True, nullable=False)
    is_lag = sdb.Column(sdb.Boolean, default=False) #True=Lag #False=Trunk
    entity_id = sdb.Column(sdb.Integer, default=1) #range 1-256 for lag or trunk
    entity_id_sub = sdb.Column(sdb.Integer, default=0) #range 1 to 4094 #0=no sub
    native_vlan = sdb.Column(sdb.Integer, default=1) #range 1-4094
    native_tag = sdb.Column(sdb.Boolean, default=False)
    allowed = sdb.Column(sdb.LargeBinary(512), default=vlans_to_bytes(vlans_from_list())) #every bit in range 1-4094 (512 bytes) turns vlan on or off
    lacp = sdb.Column(sdb.Integer, default=0) #0 not specified #1 active #2 passive
    lacp_rate = sdb.Column(sdb.Integer, default=0) #0 not specified #1 fast #2 slow
    description = sdb.Column(sdb.String(64))
    __table_args__=(sdb.Index('switch_trunk_lag_index',"switch_name","is_lag","entity_id", "entity_id_sub"),)
    def __init__(self, switch_name, is_lag, entity_id, entity_id_sub, native_vlan, native_tag, allowed,
            lacp, lacp_rate, description):
        self.switch_name= switch_name
        self.is_lag= is_lag
        self.entity_id= entity_id
        self.native_vlan= native_vlan
        self.native_tag= native_tag
        self.allowed= allowed
        self.lacp= lacp
        self.lacp_rate= lacp_rate
        self.description=description
class switch_trunk_lagSchema(ma.Schema):
    class Meta:
        fields=('id','switch_name','is_lag','entity_id','entity_id_sub','native_vlan',
                'native_tag', 'lacp', 'lacp_rate',
                'description','allowed')

class switch_mgmt(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), index=True, nullable=False, unique=True)
    ip_dhcp = sdb.Column(sdb.Boolean)
    ip_static = sdb.Column(sdb.String(128))
    default_gateway = sdb.Column(sdb.String(128))
    nameserver1 = sdb.Column(sdb.String(128))
    nameserver2 = sdb.Column(sdb.String(128))
    shutdown = sdb.Column(sdb.Boolean)
    lldp_transmit = sdb.Column(sdb.Boolean)
    lldp_receive = sdb.Column(sdb.Boolean)
    lldp_trap = sdb.Column(sdb.Boolean)
    __table_args__=(sdb.Index('switch_mgmt_index','switch_name'),)
    def __init__(self, switch_name, ip_dhcp, ip_static, default_gateway,
            nameserver1, nameserver2, shutdown, lldp_transmit, lldp_receive,
            lldp_trap):
        self.switch_name= switch_name
        self.ip_dhcp= ip_dhcp
        self.ip_static= ip_static
        self.default_gateway= default_gateway
        self.nameserver1= nameserver1
        self.nameserver2= nameserver2
        self.shutdown= shutdown
        self.lldp_transmit= lldp_transmit
        self.lldp_receive= lldp_receive
        self.lldp_trap= lldp_trap
class switch_mgmtSchema(ma.Schema):
    class Meta:
        fields = ('id', 'switch_name', 'ip_dhcp', 'ip_static', 'default_gateway', 'nameserver1', 'nameserver2', 'shutdown', 'lldp_transmit', 'lldp_receive', 'lldp_trap')

class switch_mirror_endpoint(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), nullable=False)
    endpoint = sdb.Column(sdb.String(64), nullable=False)
    mirror_source_ip = sdb.Column(sdb.String(128))
    mirror_dest_ip = sdb.Column(sdb.String(128))
    vrf = sdb.Column(sdb.String(128))
    enable = sdb.Column(sdb.Boolean)
    comment = sdb.Column(sdb.String(256))
    destination = sdb.Column(sdb.LargeBinary(80), default=mirror_to_bytes(mirror_from_list()))
    __table_args__=(sdb.Index('switch_mirror_endpoint_index',"switch_name","endpoint", unique=True),)
    def __init__(self, switch_name, endpoint, mirror_source_ip, mirror_dest_ip,
            vrf, enable, comment, destination):
        self.switch_name = switch_name
        self.endpoint = endpoint
        self.mirror_source_ip = mirror_source_ip
        self.mirror_dest_ip = mirror_dest_ip
        self.comment = comment
        self.vrf = vrf
        self.enable = enable
        self.destination = destination
class switch_mirror_endpointSchema(ma.Schema):
    class Meta:
        fields=('id', 'switch_name', 'endpoint', 'mirror_source_ip',
                'mirror_dest_ip', 'vrf', 'enable', 'comment', 'destination')

class switch_mirror_session(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), nullable=False)
    session = sdb.Column(sdb.SmallInteger, nullable=False)
    comment = sdb.Column(sdb.String(64))
    enable = sdb.Column(sdb.Boolean)
    source_interface = sdb.Column(sdb.LargeBinary(80), default=mirror_to_bytes(mirror_from_list()))
    source_interface_direction = sdb.Column(sdb.LargeBinary(160), default=rxtx_to_bytes(rxtx_from_list(size=640)))
    source_lag = sdb.Column(sdb.LargeBinary(32), default=lag_to_bytes(lag_from_list()))
    source_lag_direction = sdb.Column(sdb.LargeBinary(64), default=rxtx_to_bytes(rxtx_from_list(size=256)))
    source_vlan = sdb.Column(sdb.LargeBinary(512), default=vlans_to_bytes(vlans_from_list()))
    source_vlan_direction = sdb.Column(sdb.LargeBinary(1024), default=rxtx_to_bytes(rxtx_from_list(size=4096)))
    destination = sdb.Column(sdb.LargeBinary(80), default=mirror_to_bytes(mirror_from_list()))
    cpu = sdb.Column(sdb.Boolean)
    destination_tunnel_ip = sdb.Column(sdb.String(128))
    destination_tunnel_source = sdb.Column(sdb.String(128))
    destination_tunnel_dscp = sdb.Column(sdb.SmallInteger)
    destination_tunnel_vrf = sdb.Column(sdb.String(128))
    __table_args__=(sdb.Index('switch_mirror_session_index',"switch_name","session", unique=True),)
    def __init__(self, switch_name, session, comment, enable, source_interface, source_interface_direction, source_lag, source_lag_direction, source_vlan, source_vlan_direction, destination, cpu, destination_tunnel_ip, destination_tunnel_source, destination_tunnel_dscp, destination_tunnel_vrf):
        self.switch_name= switch_name
        self.session= session
        self.comment= comment
        self.enable= enable
        self.source_interface= source_interface
        self.source_interface_direction= source_interface_direction
        self.source_lag= source_lag
        self.source_lag_direction= source_lag_direction
        self.source_vlan= source_vlan
        self.source_vlan_direction= source_vlan_direction
        self.destination= destination
        self.cpu= cpu
        self.destination_tunnel_ip= destination_tunnel_ip
        self.destination_tunnel_source= destination_tunnel_source
        self.destination_tunnel_dscp= destination_tunnel_dscp
        self.destination_tunnel_vrf= destination_tunnel_vrf
class switch_mirror_sessionSchema(ma.Schema):
    class Meta:
        fields=('id', 'switch_name', 'session', 'comment', 'enable', 'source_interface', 'source_interface_direction', 'source_lag', 'source_lag_direction', 'source_vlan', 'source_vlan_direction', 'destination', 'cpu', 'destination_tunnel_ip', 'destination_tunnel_source', 'destination_tunnel_dscp', 'destination_tunnel_vrf')

class switch_route(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), index=True, nullable=False)
    ip_route = sdb.Column(sdb.String(128), nullable=False)
    ip_nexthop = sdb.Column(sdb.String(128), nullable=False)
    outgoing_interface = sdb.Column(sdb.String(32))
    blackhole = sdb.Column(sdb.Boolean)
    reject = sdb.Column(sdb.Boolean)
    tag = sdb.Column(sdb.Integer) #0 = no tag, >1 = tag
    distance = sdb.Column(sdb.Integer) #1 = default #range 1-255
    vrf = sdb.Column(sdb.String(128))
    description = sdb.Column(sdb.String(64))
    bfd = sdb.Column(sdb.Boolean)
    def __init__(self, switch_name, ip_route, ip_nexthop, outgoing_interface,
            blackhole, reject, tag, distance, vrf, description, bfd):
        self.switch_name= switch_name
        self.ip_route= ip_route
        self.ip_nexthop= ip_nexthop
        self.outgoing_interface= outgoing_interface
        self.blackhole= blackhole
        self.reject= reject
        self.tag= tag
        self.distance= distance
        self.vrf= vrf
        self.description= description
        self.bfd = bfd
class switch_routeSchema(ma.Schema):
    class Meta:
        fields=('id', 'switch_name', 'ip_route', 'ip_nexthop',
                'outgoing_interface', 'blackhole', 'reject', 'tag', 'distance',
                'vrf', 'description', 'bfd')

class switch_device_port(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), index=True, nullable=False)
    switch_number = sdb.Column(sdb.Integer, nullable=False)
    port = sdb.Column(sdb.Integer, nullable=False)
    sub_interface = sdb.Column(sdb.Integer, default=0)
    vrf = sdb.Column(sdb.String(128), default="")
    ip = sdb.Column(sdb.String(128), index=True, nullable=False)
    routing = sdb.Column(sdb.Boolean, default=False)
    #ref track table
    track = sdb.Column(sdb.Integer, default=0)
    #ref vrrp table
    vrrp = sdb.Column(sdb.Integer, default=0)
    vlan_access = sdb.Column(sdb.Integer, default=0) #range 1-4094
    #ref vlan trunk/lag table
    trunk = sdb.Column(sdb.Integer, default=0) #0 = no trunk
    udld = sdb.Column(sdb.Boolean, default=False)
    spantree_profile = sdb.Column(sdb.Integer, sdb.ForeignKey("switch_spantree_policy.id"), default=0, nullable=False)
    sflow = sdb.Column(sdb.Boolean, default=False)
    port_security = sdb.Column(sdb.Boolean, default=False) # does not map to specific config
    port_security_profile = sdb.Column(sdb.Integer, sdb.ForeignKey("switch_port_role_profile.id"), default=0, nullable=False)
    switch_port_policy = sdb.Column(sdb.Integer, sdb.ForeignKey("switch_port_policy.id"), default=0, nullable=False)
    poe = sdb.Column(sdb.Boolean, default=False)
    poe_allocateby=sdb.Column(sdb.Integer, default=0) #0 = none #1 = usage #2=class
    poe_priority=sdb.Column(sdb.Integer, default=0) #0 = none #1 = critical #2 = high #3=low
    poe_pre_std=sdb.Column(sdb.Boolean, default=False)
    poe_pdoverride=sdb.Column(sdb.Boolean, default=False)
    poe_class=sdb.Column(sdb.Integer,default=3) #3,4,6
    #link_poe ??? can't find documentation
    nd_snooping=sdb.Column(sdb.Boolean, default=False)
    igmp_policy=sdb.Column(sdb.Integer, sdb.ForeignKey("switch_igmp_policy.id"), default=0, nullable=False)
    lldp_policy=sdb.Column(sdb.Integer, sdb.ForeignKey("switch_lldp_policy.id"), default=0, nullable=False)
    loop_protect=sdb.Column(sdb.Boolean, default=False)
    loop_protect_action = sdb.Column(sdb.Integer, default=0) #0 none
    #1=tx-disable #2=do-not-disable #3=tx-rx-disable
    lag = sdb.Column(sdb.Integer, default=0) #1-256 - which lag if lag
    mac_notify = sdb.Column(sdb.Integer, default=0) #0 none #1 learned #2 aged
    #3 moved #4 removed
    description = sdb.Column(sdb.String(256), default="")
    shutdown = sdb.Column(sdb.Boolean, default=False)
    speed = sdb.Column(sdb.Integer, default=8) #1=10-full, #2=10-half,
    #3=100-full, #4=100-half, #5=1000-full, #6=10m-Auto, #7=100m-Auto,
    #8=1g-Auto, #9=2.5g-Auto, #10=5g-Auto, #11=10g-Auto, #12=25g-Auto,
    #13=40g-Auto, #14=50g-Auto, #15=100g-Auto
    flow_control = sdb.Column(sdb.Boolean, default=False) #true turns on rxtx
    mtu = sdb.Column(sdb.Integer, default=0) #what should the MTU be this is not IP MTU
    ip_mtu = sdb.Column(sdb.Integer, default=1500) #range 68-9198
    l3_counters = sdb.Column(sdb.Integer, default=0) #0 = off, #1 = on, #2=tx, #3=rx
    ip_urpf_check = sdb.Column(sdb.Integer, default=0) #0=0ff,#1=loose,#2=strict
    ip_directed_broadcast = sdb.Column(sdb.Boolean, default=False)
    dhcpv4_snooping = sdb.Column(sdb.Integer, default=False) #on=Trust
    ipv4_source_lockdown = sdb.Column(sdb.Boolean, default=False)
    client_track_ip = sdb.Column(sdb.Integer, default=0) #0 disable #1 enable #2 auto
    client_track_ip_interval = sdb.Column(sdb.Integer, default=60) #range 60-28000
    bfd = sdb.Column(sdb.Integer, default=0) # future
    arp_timeout = sdb.Column(sdb.Integer, default=30) #range 30-28800
    #foreign_key in arp_static on this id for static MAC ARP entries #future
    arp_ip_local_proxy = sdb.Column(sdb.Boolean, default=False)
    arp_proxy = sdb.Column(sdb.Boolean, default=False)
    arp_inspection = sdb.Column(sdb.Boolean, default=False) #true = arp inspection trust
    acl_policy = sdb.Column(sdb.Integer, sdb.ForeignKey("switch_acl_policy.id"), default=0, nullable=False)
    qos_policy = sdb.Column(sdb.Integer, sdb.ForeignKey("switch_qos_policy.id"), default=0, nullable=False)
    __table_args__=(sdb.Index('switch_device_port_index', "switch_name","switch_number", "port", unique=True),)
    def __init__(self, acl_policy=1, arp_inspection=False,
            arp_ip_local_proxy=False,
            arp_proxy=False, arp_timeout=30, bfd=0, client_track_ip="",
            client_track_ip_interval=0, description="", dhcpv4_snooping=0,
            flow_control=False, igmp_policy=1, ip="",
            ip_directed_broadcast=False,
            ip_mtu=1500, ip_urpf_check=0, ipv4_source_lockdown=False,
            l3_counters=0, lag=0, lldp_policy=1, loop_protect=False,
            loop_protect_action=0, mac_notify=0, mtu=1500, nd_snooping=False,
            poe=False,
            poe_allocateby=0, poe_class=0, poe_pdoverride=False, poe_pre_std=False,
            poe_priority="", port=0, port_security=False,
            port_security_profile=1,
            qos_policy=1, routing=False, sflow=False, shutdown=False,
            spantree_profile=1,
            speed=0, sub_interface=0, switch_name="", switch_number=0,
            switch_port_policy=1, track=0, trunk=0, udld=False, vlan_access=0,
            vrf='', vrrp=0):
        self.switch_name= switch_name
        self.switch_number= switch_number
        self.port= port
        self.sub_interface = sub_interface
        self.vrf= vrf
        self.ip= ip
        self.routing= routing
        self.track= track
        self.vrrp= vrrp
        self.vlan_access= vlan_access
        self.trunk = trunk
        self.udld= udld
        self.spantree_profile= spantree_profile
        self.sflow= sflow
        self.port_security= port_security
        self.port_security_profile= port_security_profile
        self.switch_port_policy= switch_port_policy
        self.poe= poe
        self.poe_allocateby= poe_allocateby
        self.poe_priority= poe_priority
        self.poe_pre_std= poe_pre_std
        self.poe_pdoverride= poe_pdoverride
        self.poe_class= poe_class
        self.nd_snooping= nd_snooping
        self.igmp_policy= igmp_policy
        self.lldp_policy= lldp_policy
        self.loop_protect= loop_protect
        self.loop_protect_action= loop_protect_action
        self.lag= lag
        self.mac_notify= mac_notify
        self.description= description
        self.shutdown= shutdown
        self.speed= speed
        self.flow_control= flow_control
        self.mtu= mtu
        self.ip_mtu= ip_mtu
        self.l3_counters= l3_counters
        self.ip_urpf_check= ip_urpf_check
        self.ip_directed_broadcast= ip_directed_broadcast
        self.dhcpv4_snooping= dhcpv4_snooping
        self.ipv4_source_lockdown= ipv4_source_lockdown
        self.client_track_ip= client_track_ip
        self.client_track_ip_interval= client_track_ip_interval
        self.bfd= bfd
        self.arp_timeout= arp_timeout
        self.arp_ip_local_proxy= arp_ip_local_proxy
        self.arp_proxy= arp_proxy
        self.arp_inspection= arp_inspection
        self.acl_policy= acl_policy
        self.qos_policy= qos_policy
class switch_device_portSchema(ma.Schema):
    class Meta:
        fields = ('id','acl_policy', 'arp_inspection', 'arp_ip_local_proxy', 'arp_proxy', 'arp_timeout', 'bfd', 'client_track_ip', 'client_track_ip_interval', 'description', 'dhcpv4_snooping', 'flow_control', 'igmp_policy', 'ip', 'ip_directed_broadcast', 'ip_mtu', 'ip_urpf_check', 'ipv4_source_lockdown', 'l3_counters', 'lag', 'lldp_policy', 'loop_protect', 'loop_protect_action', 'mac_notify', 'mtu', 'nd_snooping', 'poe', 'poe_allocateby', 'poe_class', 'poe_pdoverride', 'poe_pre_std', 'poe_priority', 'port', 'port_security', 'port_security_profile', 'qos_policy', 'routing', 'sflow', 'shutdown', 'spantree_profile', 'speed', 'sub_interface', 'switch_name', 'switch_number', 'switch_port_policy', 'track', 'trunk', 'udld', 'vlan_access', 'vrf', 'vrrp')

class switch_global_helpers(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    ip_addr = sdb.Column(sdb.String(256), nullable=False, index=True, unique=True)
    def __init__(self, ip_addr): 
        self.ip_addr = ip_addr
class switch_global_helpersSchema(ma.Schema):
    class Meta:
        fields = ('id','ip_addr')

class switch_bgp(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), index=True, nullable=False, unique=True)
    enable = sdb.Column(sdb.Boolean, default=True)
    bgp_timer_keepalive = sdb.Column(sdb.Integer, default=3)
    bgp_timer_hold = sdb.Column(sdb.Integer, default=10)
    maximum_paths = sdb.Column(sdb.SmallInteger, default=4)
    redist_connected = sdb.Column(sdb.Boolean, default=True)
    redist_connected_rm = sdb.Column(sdb.String(32), default="")
    redist_static = sdb.Column(sdb.Boolean, default=False)
    redist_static_rm = sdb.Column(sdb.String(32), default="")
    def __init__(self, switch_name, enable, bgp_timer_keepalive, bgp_timer_hold,
            maxium_paths,redist_connected,redist_connected_rm,redist_static,redist_static_rm):
        self.switch_name = switch_name
        self.enable = enable
        self.bgp_timer_keepalive = bgp_timer_keepalive
        self.bgp_timer_hold = bgp_timer_hold
        self.maxium_paths = maxium_paths
        self.redist_connected = redist_connected
        self.redist_connected_rm = redist_connected_rm
        self.redist_static = redist_static
        self.redist_static_rm = redist_static_rm
class switch_bgpSchema(ma.Schema):
    class Meta:
        fields = ('id', 'switch_name', 'enable', 'bgp_timer_keepalive',
        'bgp_timer_hold', 'maximum_paths', 'redist_connected',
        'redist_connected_rm', 'redist_static', 'redist_static_rm')

class switch_bgp_neighbor(BASE):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), index=True, nullable=False)
    neighbor_ip = sdb.Column(sdb.String(45), index=True, nullable=False, default="")
    remote_as = sdb.Column(sdb.String(11), index=True, nullable=False, default="")
    local_as = sdb.Column(sdb.String(11), nullable=True, default=None)
    vrf = sdb.Column(sdb.String(128), nullable=True, default=None)
    description = sdb.Column(sdb.String(128), nullable=False, default="")
    enabled = sdb.Column(sdb.Boolean, default=True)
    password = sdb.Column(sdb.String(256), nullable=True, default="")
    local_as_prepend = sdb.Column(sdb.Boolean, default=True)
    local_as_replace = sdb.Column(sdb.Boolean, default=False)
    remove_private_as = sdb.Column(sdb.Boolean, default=False)
    fast_external_failover = sdb.Column(sdb.Boolean, default=False)
    fallover_bfd = sdb.Column(sdb.Boolean, default=False)
    update_source = sdb.Column(sdb.String(39), default=None)
    update_source_type = sdb.Column(sdb.SmallInteger, default=0) #0=nothing #1=IP, 2=Loopback, 3=LAG, 4=VLAN
    bgp_timer_neighbor = sdb.Column(sdb.Boolean, default=False)
    bgp_timer_keepalive = sdb.Column(sdb.Integer, default=30)
    bgp_timer_hold = sdb.Column(sdb.Integer, default=180)
    bgp_passive = sdb.Column(sdb.Boolean, default=False)
    address_family = sdb.Column(sdb.SmallInteger, default=1)    #1 = IPv4 #2= Future IPv6
    rm_inbound = sdb.Column(sdb.String(32), default="")
    rm_outbound = sdb.Column(sdb.String(32), default="")
    __table_args__=(sdb.Index('ix_switch_bgp_neighbor_multiple',"switch_name","neighbor_ip", "remote_as", "local_as", "vrf", unique=True),)
    def __init__(self, switch_name, neighbor_ip, remote_as, local_as, vrf,
            description, enabled, password, local_as_prepend, local_as_replace,
            remove_private_as, fast_external_failover, fallover_bfd,
            update_source, update_source_type, bgp_timer_neighbor,
            bgp_timer_keepalive, bgp_timer_hold, bgp_passive, address_family,
            rm_inbound, rm_outbound):
                self.id= id
                self.switch_name= switch_name
                self.neighbor_ip= neighbor_ip
                self.remote_as= remote_as
                self.local_as= local_as
                self.vrf= vrf
                self.description= description
                self.enabled= enabled
                self.password= password
                self.local_as_prepend= local_as_prepend
                self.local_as_replace= local_as_replace
                self.remove_private_as= remove_private_as
                self.fast_external_failover= fast_external_failover
                self.fallover_bfd= fallover_bfd
                self.update_source= update_source
                self.update_source_type= update_source_type
                self.bgp_timer_neighbor= bgp_timer_neighbor
                self.bgp_timer_keepalive= bgp_timer_keepalive
                self.bgp_timer_hold= bgp_timer_hold
                self.bgp_passive= bgp_passive
                self.address_family= address_family
                self.rm_inbound= rm_inbound
                self.rm_outbound= rm_outbound
class switch_bgp_neighborSchema(ma.Schema):
    class Meta:
        fields = ('id', 'switch_name', 'neighbor_ip', 'remote_as', 'local_as',
                'vrf', 'description', 'enabled', 'password', 'local_as_prepend',
                'local_as_replace', 'remove_private_as',
                'fast_external_failover', 'fallover_bfd', 'update_source',
                'update_source_type', 'bgp_timer_neighbor',
                'bgp_timer_keepalive', 'bgp_timer_hold', 'bgp_passive',
                'address_family', 'rm_inbound', 'rm_outbound')

class switch_device_l3vlans(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    switch_name = sdb.Column(sdb.String(128), index=True, nullable=False)
    vlan = sdb.Column(sdb.Integer, index=True, nullable=False)
    ip = sdb.Column(sdb.String(128), index=True, nullable=False)
    # foreign ref multiple to tied to site/vlan
    # ip address / secondary
    # helper address / vrf name
    # bootp gateway
    # forward protocol / integer (type)
    # arp IPv4 / MAC
    track = sdb.Column(sdb.Integer, default=0)
    vrrp = sdb.Column(sdb.Integer, default=0)
    vrf = sdb.Column(sdb.String(128), default="")
    description = sdb.Column(sdb.String(256), default="")
    shutdown = sdb.Column(sdb.Boolean, default=False)
    arp_timeout = sdb.Column(sdb.Integer, default=30)
    ip_mtu = sdb.Column(sdb.Integer, default=1500)
    l3_counters = sdb.Column(sdb.Boolean, default=True)
    ip_directed_broadcast = sdb.Column(sdb.Boolean, default=True)
    ip_neighbor_flood = sdb.Column(sdb.Boolean, default=False)
    ip_dhcp = sdb.Column(sdb.Boolean, default=False)
    ip_proxy_arp = sdb.Column(sdb.Boolean, default=False)
    ip_policy_in = sdb.Column(sdb.String(256), default="")
    ip_acl_in = sdb.Column(sdb.String(256), default="")
    ip_acl_out = sdb.Column(sdb.String(256), default="")
    ip_igmp = sdb.Column(sdb.Integer, default=2)
    ip_igmp_querier = sdb.Column(sdb.Boolean, default=False)
    ip_enable_helpers = sdb.Column(sdb.Boolean, default=False)
    ip_helpers_use_defaults = sdb.Column(sdb.Boolean, default=True)
    __table_args__=(sdb.Index('switch_device_l3vlans_index', "switch_name", "vlan", unique=True),)
    def __init__(self, switch_name, vlan, ip, track, vrrp, vrf, description,
            shutdown, arp_timeout, ip_mtu, l3_counters, ip_directed_broadcast,
            ip_neighbor_flood, ip_dhcp, ip_proxy_arp, ip_policy_in, ip_acl_in,
            ip_acl_out, ip_igmp, ip_igmp_querier, ip_enable_helpers, ip_helpers_use_defaults):
        self.switch_name = switch_name
        self.vlan = vlan
        self.ip = ip
        self.track = track
        self.vrrp = vrrp
        self.vrf = vrf
        self.description = description
        self.shutdown = shutdown
        self.arp_timeout = arp_timeout
        self.ip_mtu = ip_mtu
        self.l3_counters = l3_counters
        self.ip_directed_broadcast = ip_directed_broadcast
        self.ip_neighbor_flood = ip_neighbor_flood
        self.ip_dhcp = ip_dhcp
        self.ip_proxy_arp = ip_proxy_arp
        self.ip_policy_in = ip_policy_in
        self.ip_acl_in = ip_acl_in
        self.ip_acl_out = ip_acl_out
        self.ip_igmp = ip_igmp
        self.ip_igmp_querier = ip_igmp_querier
        self.ip_enable_helpers = ip_enable_helpers
        self.ip_helpers_use_defaults = ip_helpers_use_defaults
class switch_device_l3vlansSchema(ma.Schema):
    class Meta:
        fields = ('id', 'switch_name', 'vlan', 'ip', 'track', 'vrrp', 'vrf', 'description', 'shutdown',
        'arp_timeout', 'ip_mtu', 'l3_counters', 'ip_directed_broadcast',
        'ip_neighbor_flood', 'ip_dhcp', 'ip_proxy_arp', 'ip_policy_in', 'ip_acl_in',
        'ip_acl_out', 'ip_igmp', 'ip_igmp_querier', 'ip_enable_helpers', 'ip_helpers_use_defaults')

switch_mgmt_schema = switch_mgmtSchema()
switches_mgmt_schema = switch_mgmtSchema(many=True)
cp_region_schema = cp_regionSchema()
cp_regions_schema = cp_regionSchema(many=True)
cp_site_profile_schema = cp_site_profileSchema()
cp_site_profiles_schema = cp_site_profileSchema(many=True)
switch_device_port_schema = switch_device_portSchema()
switch_device_ports_schema = switch_device_portSchema(many=True)
switch_trunk_lag_schema = switch_trunk_lagSchema()
switch_trunks_lags_schema = switch_trunk_lagSchema(many=True)
switch_spantree_policy_schema = switch_spantree_policySchema()
switch_spantree_policies_schema = switch_spantree_policySchema(many=True)
switch_lldp_policy_schema = switch_lldp_policySchema()
switch_lldp_policies_schema = switch_lldp_policySchema(many=True)
switch_role_policy_schema = switch_port_role_profileSchema()
switch_role_policies_schema = switch_port_role_profileSchema(many=True)
switch_acl_polcy_schema = switch_acl_policySchema()
switch_acl_policies_schema = switch_acl_policySchema(many=True)
switch_port_policy_schema = switch_port_policySchema()
switch_port_policies_schema = switch_port_policySchema(many=True)
switch_qos_policy_schema = switch_qos_policySchema()
switch_qos_policies_schema = switch_qos_policySchema(many=True)
switch_igmp_policy_schema = switch_igmp_policySchema()
switch_igmp_policies_schema = switch_igmp_policySchema(many=True)
dns_server_schema = DNSServerSchema()
dns_servers_schema = DNSServerSchema(many=True)
sla_locations_schema = sla_locationsSchema(many=True)
sla_location_schema = sla_locationsSchema()
ntp_servers_schema = NTPServerSchema(many=True)
ntp_server_schema = NTPServerSchema()
switch_multi_vars_schema = switch_multi_varsSchema(many=True)
switch_multi_var_schema = switch_multi_varsSchema()
switch_device_multi_vars_schema = switch_device_multi_varsSchema(many=True)
switch_device_multi_var_schema = switch_device_multi_varsSchema()
global_vlans_schema = global_vlansSchema(many=True)
global_vlan_schema = global_vlansSchema()
gmi_sites_schema = gmi_sitesSchema(many=True)
gmi_site_schema = gmi_sitesSchema()
site_vlans_schema = site_vlansSchema(many=True)
site_vlan_schema = site_vlansSchema()
switch_site_multi_vars_schema = switch_site_multi_varsSchema(many=True)
switch_site_multi_var_schema = switch_site_multi_varsSchema()
switch_models_schema = switch_modelsSchema(many=True)
switch_model_schema = switch_modelsSchema()
site_switches_schema = site_switchesSchema(many=True)
site_switch_schema = site_switchesSchema()
switch_device_vlans_schema = switch_device_vlansSchema(many=True)
switch_device_vlan_schema = switch_device_vlansSchema()
switch_device_l3vlans_schema = switch_device_l3vlansSchema(many=True)
switch_device_l3vlan_schema = switch_device_l3vlansSchema()
switch_ipv4_addresses_schema = switch_ipv4_addressesSchema(many=True)
switch_ipv4_address_schema = switch_ipv4_addressesSchema()
switch_route_schema = switch_routeSchema()
switch_routes_schema = switch_routeSchema(many=True)
switch_mirror_endpoint_schema = switch_mirror_endpointSchema()
switch_mirror_endpoints_schema = switch_mirror_endpointSchema(many=True)
switch_mirror_session_schema = switch_mirror_sessionSchema()
switch_mirror_sessions_schema = switch_mirror_sessionSchema(many=True)
switch_bgp_schema = switch_bgpSchema()
switches_bgp_schema = switch_bgpSchema(many=True)
switch_bgp_neighbors_schema = switch_bgp_neighborSchema(many=True)
switch_bgp_neighbor_schema = switch_bgp_neighborSchema()
switch_global_helpers_schema = switch_global_helpersSchema(many=True)
switch_global_helper_schema = switch_global_helpersSchema()

#any new tables that get added that are key'd off the switch_name should be
#here - this is used for renaming a switch
name_key_tables = {
        "site_switches": {'dbentity':site_switches, 'single':site_switch_schema, 'multiple':site_switches_schema},
        "switch_device_multi_vars": {'dbentity': switch_device_multi_vars, 'single':switch_device_multi_var_schema, 'multiple':switch_device_multi_vars_schema},
        "switch_device_vlans": {'dbentity': switch_device_vlans, 'single':switch_device_vlan_schema, 'multiple':switch_device_vlans_schema},
        "switch_ipv4_addresses": {'dbentity': switch_ipv4_addresses, 'single':switch_ipv4_address_schema, 'multiple':switch_ipv4_addresses_schema},
        "switch_trunk_lag": {'dbentity': switch_trunk_lag, 'single':switch_trunk_lag_schema, 'multiple':switch_trunks_lags_schema},
        "switch_mgmt": {'dbentity': switch_mgmt, 'single':switch_mgmt_schema, 'multiple':switches_mgmt_schema},
        "switch_mirror_endpoint": {'dbentity': switch_mirror_endpoint, 'single':switch_mirror_endpoint_schema, 'multiple':switch_mirror_endpoints_schema},
        "switch_mirror_session": {'dbentity': switch_mirror_session, 'single':switch_mirror_session_schema, 'multiple':switch_mirror_sessions_schema},
        "switch_route": {'dbentity':switch_route, 'single':switch_route_schema, 'multiple':switch_routes_schema},
        "switch_device_port": {'dbentity': switch_device_port, 'single':switch_device_port_schema, 'multiple':switch_device_ports_schema},
        "switch_bgp": {'dbentity': switch_bgp, 'single':switch_bgp_schema, 'multiple':switches_bgp_schema},
        "switch_bgp_neighbor": {'dbentity': switch_bgp_neighbor, 'single':switch_bgp_neighbor_schema, 'multiple':switch_bgp_neighbors_schema},
        "switch_device_l3vlans": {'dbentity': switch_device_l3vlans, 'single':switch_device_l3vlan_schema, 'multiple':switch_device_l3vlans_schema}
}


with app.app_context():
    syslog.info("Trying to create new tables if any")
    sdb.create_all()


if os.path.exists('/.dockerenv'):
    app.secret_key = grabPassVault(secret_path="networkteam/network-ui-kaos/prd/secrets",
                         fetchkey="secret_key")
else:
    app.secret_key = grabPass("/etc/network/data/mid_password_file.txt","secret_key")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#API_SWAGGER_HOST = "https://vl-kaosdev01"
#API_SWAGGER_HOST = "https://jfbwwwkaosp1"
API_SWAGGER_HOST = "https://kaos.backend-network-api.genmills.com"

K8_ENV = False
try:
    socket.gethostbyname_ex("metadata.google.internal")
    # syslog.info("Environment is:{}".format(env.Name))
    if env.Name == "Development":
        LDAP_SERVER = "guc1dc.genmills.com"
        API_SWAGGER_HOST = "https://network-api-kaos-nonprod.k8s.genmills.com"
    else:
        LDAP_SERVER = "guc1dc.genmills.com"
        API_SWAGGER_HOST = "https://kaos.backend-network-api.genmills.com"
    LDAP_PORT = "3269"
    import redis

    redis_cache = redis.Redis(host='redis-master',port=6379)
    redis_cache.set('foo', 'bar')
    test_value = redis_cache.get('foo')
    syslog.info("REDIS CACHE TEST VALUE: "+str(test_value))
    if test_value != b'bar':
        syslog.info("REDIS CACHE NOT WORKING")
    else:
        syslog.info("REDIS CACHE WORKING")
    K8_ENV = True
except socket.gaierror:
    LDAP_SERVER = "mgolbdc.genmills.com"
    LDAP_PORT = "3269"
# syslog.info("LDAP_SERVER_CONNECTING IS: "+str(LDAP_SERVER))
LDAP_BIND_USER = "CN=M1IS574,OU=Users,OU=MGO,OU=Sites,DC=genmills,DC=com"
if os.path.exists('/.dockerenv'):
    LDAP_BIND_PASS = grabPassVault("networkteam/network-ui-kaos/prd/mids-pwds","m1is574")
    if env.Name == "Development":
        API_SWAGGER_HOST = "https://network-api-kaos-nonprod.k8s.genmills.com"
    else:
        API_SWAGGER_HOST = "https://kaos.backend-network-api.genmills.com"
    
else:
    LDAP_BIND_PASS = grabPass("/etc/network/data/mid_password_file.txt","m1is574")
LDAP_MEMBER_DN = "CN=SAMURAI_USERS,OU=Other Groups,OU=IS Security Groups,OU=Information Systems,DC=genmills,DC=com"
LDAP_BASE_DN = "DC=genmills,DC=com"

# FUNCTIONS #

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc



class User(UserMixin):
    def __init__(self, user):
        self.username = user

    def __repr__(self):
        return self.username

    def get_id(self):
        return self.username

@app.before_request
def make_session_permanent():
    session.permanent=True
    app.permanent_session_lifetime=timedelta(minutes=15)
    session.modified = True



@app.before_request
def before_request():
    if (not os.path.exists('/.dockerenv')) and (not request.is_secure):
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)



@login_manager.user_loader
def load_user(id):
    try:
        user = User(id)
        return user
    except:
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        form=request.form
        if form["password"].encode('utf-8') != "":
            user = form["username"].encode('utf-8')
            upswd = form["password"].encode('utf-8')
            #criteria=ldap.filter.filter_format('(&(objectClass=user)(sAMAccountName=%s))',user)
            #criteria='(&(objectClass=user)(sAMAccountName='+ldap.filter.escape_filter_chars(user)+')(memberof='+ldap.filter.escape_filter_chars(LDAP_MEMBER_DN)+'))'
            criteria='(&(objectClass=user)(sAMAccountName='+ldap.filter.escape_filter_chars(user.decode())+')(memberof='+ldap.filter.escape_filter_chars(LDAP_MEMBER_DN)+'))'
            attributes = ['displayName']
            result_dn = None
            result_attrs = None
            try:
                ldap.protocol_version = 3
                if not os.path.exists('/.dockerenv'):
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
                else:
                    ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, '/etc/ssl/certs')
                    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt')
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
                    ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
                # ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)
                ldap.set_option(ldap.OPT_REFERRALS, 0)
                ld = ldap.initialize("ldaps://"+LDAP_SERVER+":"+LDAP_PORT)
                # ld.set_option(ldap.OPT_X_TLS_PROTOCOL_MIN, 0x301)
                result = ld.bind_s(LDAP_BIND_USER, LDAP_BIND_PASS)
                results = ld.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, criteria, attributes)
                for result in results:
                    result_dn=result[0]
                    result_attrs=result[1]
    #                print(result_dn)
    #            if result_attrs:
    #                if "member" in result_attrs:
    #                    for member in result_attrs["member"]:
    #                        print (member)
                ld.unbind()
                if result_dn:
                    session["name"] = result_dn.split(",")[0].split("=")[1]
                    #print ("!!!!!!!!!!!!!!!!!!!!!!!!! Found user ", result_dn, " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                else:
                    #print ("************************* No user found in group ",LDAP_MEMBER_DN," matching sAMAccountName ",user," **********************************")
                    syslog.info("{} USER NOT FOUND, SOURCE: {}".format(user, request.remote_addr))
                    return render_template("login.html", message="Authentication issue", auth=get_auth())
            except Exception as e:
                syslog.info("{} FAILURE TO BIND OR IDENTIFY AUTHORIZED USER, SOURCE: {} due to {}".format(user, request.remote_addr, e))
                return render_template("login.html", message="Authentication issue", auth=get_auth())
                # return redirect("/samurai", code=301)
            try:
                ldap.protocol_version = 3
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
     #           ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)
                ldap.set_option(ldap.OPT_REFERRALS, 0)
                ld = ldap.initialize("ldaps://"+LDAP_SERVER+":"+LDAP_PORT)
                result2 = ld.bind_s(result_dn, form["password"].encode('utf-8'))
                auth_user_only_can_run_this = ld.search_s("dc=genmills,dc=com",ldap.SCOPE_SUBTREE,'userPrincipleName={}'.format(user),['cn'])
                result2_dn=result2[0]
                #print ("Result2_dn ",result2_dn)
                if result2_dn == 97:
                    #print ("Hey you logged in.  YAY FOR YOU!!") 
                    syslog.info("{} ({}) AUTHENTICATION SUCCESSFUL, SOURCE: {}".format(session["name"],user, request.remote_addr))
                    thisuser = User(user)
                    login_user(thisuser)
                    flash("Logged in successfully.")
                    next = request.args.get('next')
                    session['token'] = get_api_auth_token(user, upswd)
                    #print ("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD: ", thisuser, " ", thisuser.is_authenticated)
                    #print (result_dn)
                    result3 = ld.search_s("dc=genmills,dc=com",ldap.SCOPE_SUBTREE,"(|(&(objectClass=group)(member={})))".format(result_dn),['cn'])
                    session["authSwitches"] = False
                    if sys.version_info[0] > 2:
                        authSwitches = {'cn': [b'NETWORK-SWITCH-MGMT']}
                    else:
                        authSwitches = {'cn': ['NETWORK-SWITCH-MGMT']}
                    for group in result3:
                        #print (group[1])
                        if group[1] == authSwitches:
                            session["authSwitches"] = True
                            break
                    #print (session["authSwitches"])
                    #print (result3)
                    
                    if not os.path.exists('/.dockerenv') and not is_safe_url(next):
                        return render_template("login.html",
                                message="Authentication issue", auth=get_auth())
                    
                    
                    return redirect(next or "/", code=301)
                else:
                    #print ("You failed.  Failed.  Failed.")
                    syslog.info("{} AUTHENTICATION FAILURE, BAD USER OR PW, SOURCE: {}".format(user, request.remote_addr))
                    return render_template("login.html", message="Authentication issue", auth=get_auth())
            except Exception as e:
                syslog.info("{} FAILURE TO CONNECT OR AUTHORIZE, SOURCE: {} due to {}".format(user, request.remote_addr, e))
                return render_template("login.html", message="Authentication issue", auth=get_auth())
    return render_template("login.html", auth=get_auth())

@app.route('/logout', methods=['POST','GET'])
@login_required
def logout():
    try:
        app.permanent_session_lifetime=0
        user=session["name"][:]
        logout_user()
        session.modified=True
        syslog.info("{} LOGGED OUT, SOURCE: {}".format(user, request.remote_addr))
    except Exception as e:
        return render_template("login.html", message="Logout error",
                auth=get_auth())
    return redirect('/login', code=301)


def get_api_auth_token(usr, pswd):
    try:
        url = "{}/api/v1/auth/token".format(API_SWAGGER_HOST)
        auth = (usr, pswd)
        data = {'name': usr}
        res = requests.post(url, data=data, auth=auth, verify=False)
        return res.json().get('token', None)
    except Exception as e:
        print("Error occured because "+str(e))

        
def get_sites_data_dynseg():
    sql_obj = sql(dbUser="dan", dbPassword=dbpw, dbHost=env.DB)
    queries = ["select site from gmi_sites where active = 1;",
               "select site from cp_site_profile;"]
    sites = []
    for query in queries:
        sql_obj.query(query)
        gmiSites = {"result" : sql_obj.getAllRows()}
        res = gmiSites['result']
        for s_res in res:
            sites.append(s_res['site'])
    return sorted(list(set(sites)))



'''
@app.route('/dynamic-segmentation-ui', methods=['GET', 'POST'])
@login_required
def pre_conf_dyn_seg():
    if request.method == "POST":
        sites = get_sites_data_dynseg()
        userEmail = request.form.get('useremail')
        addtoClearPass = bool(request.form.get('addtoClearpass') == "clearpass")
        siteName = request.form.get('sitename')
        oobEnabled = bool(request.form.get('OOBEnabled'))
        controllerPresence = bool(request.form.get('siteController'))
        baseconfigPresence = bool(request.form.get('BaseConfigProvision'))
        switchIP = request.form.get('SwitchIP')
        adminVlan = int(request.form.get('adminvlan'))
        voiceVlan = int(request.form.get('voicevlan'))
        switchModel = request.form.get('modeltype')
        sourceVlan = int(request.form.get('sourcedvlan'))
        pControllerIP = ''
        sControllerIP = ''
        databandIP = ''
        switchIdentifier = ''
        assert siteName != "Choose..."
        if controllerPresence == True:
            pControllerIP = request.form.get('pcontroller')
            assert pControllerIP
            sControllerIP = request.form.get('scontroller')
        if baseconfigPresence == True:
            databandIP = request.form.get('dataIPAddress')
            switchIdentifier = request.form.get('switchidentifier')
        payload = {
            "site_name": siteName,
            "user_email": userEmail,
            "oobm": oobEnabled,
            "add_to_clearpass": addtoClearPass,
            "mgmt_ip": switchIP,
            "data_ip": databandIP,
            "base_config": baseconfigPresence,
            "p_controller_ip": pControllerIP,
            "controller": controllerPresence,
            "voice_vlan": voiceVlan,
            "admin_vlan": adminVlan,
            "model": switchModel,
            "s_controller_ip": sControllerIP,
            "sourced_vlan": sourceVlan,
            "switch_name": switchIdentifier
        }
        url1 = "https://vl-kaosdev01/api/v1/pre-config/switch-dynamic-segmentation"
        apiToken = session.get('token', None)
        if apiToken:
            headers = {'Authorization': apiToken, 
                       'Content-Type': 'application/json'}
            try:
                res = requests.post(url1, json=payload, headers=headers, verify=False)
                # parsed_res = json.dumps(res.json(), indent=4)
                parsed_res = res.json()
                return render_template("pre_conf_dyn_seg.html", sites=sites, response=parsed_res,
                                       auth=get_auth())
            except Exception as e:
                return render_template("pre_conf_dyn_seg.html", sites=sites, response=e.message,
                                       auth=get_auth())
    sites = get_sites_data_dynseg()    
    return render_template("test_ds_vue.html", sites=sites, auth=get_auth())
    # return render_template("pre_conf_dyn_seg.html", sites=sites, auth=get_auth())
'''

'''
@app.route('/backend-apis-redirect')
def redirect_to_backend_apis():
    if env.Name == "PROD":
        backend_container_url = 'https://kaos.backend-network-api.genmills.com/api/swagger-ui/'
    else:
        backend_container_url = 'https://kaos.backend-network-api.genmills.com/api/swagger-ui/'
    return redirect('https://kaos.backend-network-api.genmills.com/api/swagger-ui/')
'''

@app.route('/dynamic-segmentation-ui', methods=['GET'])
@login_required
def pre_conf_dyn_seg():
    sites = get_sites_data_dynseg()
    return render_template("vue_os_dyn_seg.html", sites=sites, auth=get_auth())


#def delete_f5_node(mgmt, node_names):
#    for node_name in node_names:
#        if mgmt.tm.ltm.nodes.node.exists(name=node_name):
#            node = mgmt.tm.ltm.nodes.node.load(name=node_name)
#            print("Node found: '%s'" % node_name)
#            try:
#                node.delete()
#                print("F5 Node Deleted: '%s'" % node_name)
#                delete_node(node_name)
#                print("Database Node Deleted: '%s'" % node_name)
#            except Exception as e:
#                error_data = ()
#                error_list = error_data.append(node_name)
#                print("Unable to Delete Node." + error_list)
#                print("Error: '%s'" % e.message)
#        else:
#            print("Node not found.")


#def delete_node(node_name):
#    #for node_name in node_names:
#    query = 'match (n:Node {name:' + "\"" + node_name + "\"" + '}) DELETE n'
#    results = graph.run(query)
#    if results:
#        print("You deleted: " + node_name)
#    else:
#        print("The node does not exist")


#def display_test_nodes():
#    query = "Match (n:Node) where n.name =~ 'kongt.*' return n"
#    results = graph.run(query).data()
#    req_data = []
#    for record in results:
#        unused_node = {"name": record['n']['name'], "address": record['n']['address']}
#        req_data.append(unused_node)
#    return req_data

#def display_unused_nodes():
#    #query = "Match (n:Node) where n.name =~ 'kongt.*' return n"
#    #query = "match (n:Node) where not (n)-[:NODE_IN]->()-[:POOL_IN]->() return distinct n order by n.name"
#    query = "match (n:Node) where not (n)-->() return n"
#    results = graph.run(query).data()
#    req_data = []
#    for record in results:
#        unused_node = {"name": record['n']['name'], "address": record['n']['address']}
#        req_data.append(unused_node)
#    return req_data


#def display_load_dates():
#    query = "MATCH (n:F5) RETURN n"
#    results = graph.run(query).data()
#    req_data =[]
#    for record in results:
#        load_date = {"date": record['n']['date']}
#        req_data.append(load_date)
#    return req_data


#def display_F5s():
#    query = "MATCH (n:F5) RETURN n"
#    results = graph.run(query).data()
#    req_data =[]
#    for record in results:
#        f5name = {"name": record['n']['name'], "bolt_port": record['n']['bolt_port']}
#        req_data.append(f5name)
#    return req_data


#def display_unused_pools():
#    query = "match (n:Pool) where not (n)--() return n"
#    results = graph.run(query).data()
#    req_data = []
#    for record in results:
#        unused_vip = {"name": record['n']['name']}
#        # req_data.append((record['n']['name'], str(record['n']['address'])))
#        req_data.append(unused_vip)
#    return req_data


#def display_unused_vips():
#    query = "match (n:VIP) where not (n)--() return n"
#    results = graph.run(query).data()
#    req_data = []
#    for record in results:
#        unused_vip = {"name": record['n']['name']}
#        # req_data.append((record['n']['name'], str(record['n']['address'])))
#        req_data.append(unused_vip)
#    return req_data


#def display_num_nodes():
#    query = "match (n:Node) where not (n)--() return count(n) as num_nodes"
#    results = graph.run(query).data()
#    return results


#def display_num_pools():
#    query = "match (n:Pool) where not (n)--() return count(n) as num_pools"
#    results = graph.run(query).data()
#    return results


#def display_num_vips():
#    query = "match (n:VIP) where not (n)--() return count(n) as num_vips"
#    results = graph.run(query).data()
#    return results

@app.route('/router_test_get.htm')
def router_test_get():
     return render_template('router_test_get.htm', auth=get_auth())


@app.route('/healthz')
def check_app_health():
    if (os.path.exists('/.dockerenv')):
        return jsonify({"status": "OK"}), 200


@app.route('/livez')
def check_app_live():
    if (os.path.exists('/.dockerenv')):
        return jsonify({"status": "OK"}), 200

@app.route('/readyz')
def check_app_ready():
    if (os.path.exists('/.dockerenv')):
        return jsonify({"status": "OK"}), 200


'''
health = HealthCheck()
app.add_url_rule("/healthz", "healthcheck", view_func=lambda: health.run())
'''

@app.route('/router_test_get')
def router_test_get_without():
     return render_template('router_test_get.htm', auth=get_auth())

#@app.route('/f5', methods=['GET', 'POST'])
#def f5():
#    def get_data():
#        global graph
#        n4jpw =  grabPass("/mnt/data1/network/data/mid_password_file.txt","neo4j")
#        graph = Graph("bolt://172.25.200.36:7687", user="neo4j", password=n4jpw)
#        global f5names
#        f5names = display_F5s()
#
#        req_data = []
#        #for i in range(0, 3):
#        for f5name in f5names:
#            server_name = f5name['name']
#            print(server_name)
#            #req_data.append(server_name)
#            bolt_number = str(f5name['bolt_port'])
#            graph = Graph("bolt://172.25.200.36:" + bolt_number, user="neo4j",
#                    password=n4jpw)
#                #print(graph)
#                #num_nodes = display_num_nodes()
#            global num_nodes
#            num_nodes = display_num_nodes()
#            for value in num_nodes:
#                num_nodes2 = (value["num_nodes"])
#                #num_vips = display_num_vips()
#                #req_data.append(num_nodes2)
#            global num_vips
#            num_vips = display_num_vips()
#            for value in num_vips:
#                num_vips2 = value["num_vips"]
#                #req_data.append(num_vips2)
#            global num_pools
#            num_pools = display_num_pools()
#            for value in num_pools:
#                num_pools2 = value["num_pools"]
#                #req_data.append(num_vips2)
#            req_data.append(server_name)
#            req_data.append(num_nodes2)
#            req_data.append(num_pools2)
#            req_data.append(num_vips2)
#        return req_data
#
#    datas = get_data()
#
#    print(datas)
#    col = 4
#    datas2 = [datas[i:i+col] for i in range(0, len(datas), col)]
#    #dicts = [datas[i:i+col] for i in range(0, len(datas), col)]
#    print("this is data2")
#    print(datas2)
#    def convert(list):
#        return tuple(list)
#
#    converted_tuple = convert(datas2)
#    #converted_tuple2 = dict(converted_tuple)
#    print("this is data3")
#    print(converted_tuple)
#    fields = ['server_name', 'num_nodes', 'num_pools', 'num_vips']
#    converted_fields = convert(fields)
#    print("this is the converted fields")
#    print(converted_fields)
#    #dicts = [dict(zip(fields, d)) for d in datas2]
#    dicts = [OrderedDict(zip(converted_fields, d)) for d in converted_tuple]
#    #dicts = dict(zip(fields, converted_tuple))
#    #dicts = dict(map(None, fields, datas2)
#    #print("this is data4")
#    #print(dicts)
#
#    #dicts = dict(sorted(sorted_dicts.items(), key=lambda x: x[0]))
#    print(dicts)
#
#    if request.method == 'POST':
#        result = request.form
#        for key, value in result.items():
#            print("You are connecting to database: " + value)
#            global value2
#            value2 = value.split("-")
#        global graph
#        graph = Graph(str(value2[1]), user="neo4j", password=n4jpw)
#        print("Your database IP: " + value2[1])
#        print("Your f5 server name: " + value2[0])
#
#        # all functionalities
#        flash(value2[0])
#        load_dates = display_load_dates()
#        unused_nodes = display_unused_nodes()
#        unused_vips = display_unused_vips()
#        return render_template("main_page.html", auth=get_auth(), result=result, unused_nodes=unused_nodes, unused_vips=unused_vips,
#                               load_dates=load_dates)
#
#
#
#    return render_template("f5.html", auth=get_auth(), f5names=f5names, dicts=dicts, num_pools=num_pools, num_nodes=num_nodes, num_vips=num_vips)
#
#@app.route("/f5/main_page", methods=['POST', 'GET'])
#def main_page():
#    if request.method == 'POST':
#        result = request.form
#        for key, value in result.items():
#            print("You are connecting to database: " + value)
#            global value2
#            value2 = value.split("-")
#        global graph
#        graph = Graph(str(value2[1]), user="neo4j", password=n4jpw)
#        print("Your database IP: " + value2[1])
#        print("Your f5 server name: " + value2[0])
#
#        # all functionalities
#        flash(value2[0])
#        load_dates = display_load_dates()
#        unused_nodes = display_unused_nodes()
#        unused_vips = display_unused_vips()
#        return render_template("main_page.html", auth=get_auth(), result=result, unused_nodes=unused_nodes, unused_vips=unused_vips,
#                               load_dates=load_dates)
#    else:
#        return render_template("main_page.html", auth=get_auth())
#
#@app.route('/f5/delete', methods=['POST'])
#def delete_node():
#    nodes = request.form["names"]
#    nodes = nodes.split(",")
#    cli_args = value2[0]
#    print("You are connected to: " + cli_args)
#    username = "m112473"
#    password = grabPass("/mnt/data1/network/data/mid_password_file.txt","M112473")
#    mgmt = ManagementRoot(cli_args, username, password)
#    delete_f5_node(mgmt, nodes)
#    #delete_node(nodes)
#    return render_template("main_page.html", auth=get_auth())
#
@app.route("/rest/v1/global-dhcp", methods=['GET'])
@app.route("/rest/v1/global-dhcp/byType", methods=['GET'])
@app.route("/rest/v1/global-dhcp/byType/<dhcp_type>", methods=['GET'])
@app.route("/rest/v1/global-dhcp/bySite", methods=['GET'])
@app.route("/rest/v1/global-dhcp/bySite/<site>", methods=['GET'])
@app.route("/rest/v1/global-dhcp/bySite/<site>/byType/<dhcp_type2>", methods=['GET'])
@login_required
def get_global_dhcp(site=None, dhcp_type=None, dhcp_type2=1):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    if request.url_rule.rule == "/rest/v1/global-dhcp/byType/<dhcp_type>":
        if (dhcp_type==None):
            query = """
                select
                    gmi_sites.id as site_id,
                    gmi_sites.site as site,
                    cp_region.id as region,
                    cp_region.primary_ip as clearpass_primary_ip,
                    cp_region.primary as clearpass_primary_name,
                    cp_region.name as region_name,
                    gds.name as dhcp_name,
                    gds.primary_ip as dhcp_primary_ip,
                    gds.primary as dhcp_primary,
                    gds.type as dhcp_type,
                    gds.secondary_ip as dhcp_secondary_ip,
                    gds.secondary as dhcp_secondary
                from
                    gmi_sites,
                    cp_region,
                    global_dhcp_server as gds
                where
                    (left(gds.site,3)=(CASE when dhcp_override is not null and trim(dhcp_override) <> "" then gmi_sites.dhcp_override else gmi_sites.site end) or left(gds.site,4)=(CASE when
                    gmi_sites.dhcp_override is not null and trim(dhcp_override) <> "" then gmi_sites.dhcp_override else gmi_sites.site end))
                    and gmi_sites.region=cp_region.id;
            """
        else:
             query = """
                select
                    gmi_sites.id as site_id,
                    gmi_sites.site as site,
                    cp_region.id as region,
                    cp_region.primary_ip as clearpass_primary_ip,
                    cp_region.primary as clearpass_primary_name,
                    cp_region.name as region_name,
                    gds.name as dhcp_name,
                    gds.primary_ip as dhcp_primary_ip,
                    gds.primary as dhcp_primary,
                    gds.type as dhcp_type,
                    gds.secondary_ip as dhcp_secondary_ip,
                    gds.secondary as dhcp_secondary
                from
                    gmi_sites,
                    cp_region,
                    global_dhcp_server as gds
                where
                    (left(gds.site,3)=(CASE when dhcp_override is not null and trim(dhcp_override) <> "" then gmi_sites.dhcp_override else gmi_sites.site end) or left(gds.site,4)=(CASE when
                    gmi_sites.dhcp_override is not null and trim(dhcp_override) <> "" then gmi_sites.dhcp_override else gmi_sites.site end))
                    and gds.type={}
                    and gmi_sites.region = cp_region.id;                    
            """.format(dhcp_type)        
    else:
        if (site==None):
            query = """
                select
                    gmi_sites.id as site_id,
                    gmi_sites.site as site,
                    cp_region.id as region,
                    cp_region.primary_ip as clearpass_primary_ip, 
                    cp_region.primary as clearpass_primary_name,
                    cp_region.name as region_name,
                    cp_region.hub_code as hub_code_override,
                    gds.name as dhcp_name,
                    gds.primary_ip as dhcp_primary_ip,
                    gds.primary as dhcp_primary,
                    gds.type as dhcp_type,
                    gds.secondary_ip as dhcp_secondary_ip,
                    gds.secondary as dhcp_secondary,
                    gds2.name as did_we_join
                from
                    gmi_sites,
                left join cp_region on gmi_sites.region=cp_region.id
                left join global_dhcp_server as gds2 on gds2.site=gmi_sites.site
                left join global_dhcp_server as gds on gds.site=(CASE when gmi_sites.dhcp_override is not null and trim(dhcp_override) <> "" then gmi_sites.dhcp_override when gds2.name is
                null then cp_region.hub_code else gmi_sites.site end)
            """
        else:
            query = """
                select
                    gmi_sites.id as site_id,
                    gmi_sites.site as site,
                    cp_region.id as region,
                    cp_region.primary_ip as clearpass_primary_ip, 
                    cp_region.primary as clearpass_primary_name,
                    cp_region.name as region_name,
                    cp_region.hub_code as hub_code_override,
                    gds.name as dhcp_name,
                    gds.primary_ip as dhcp_primary_ip,
                    gds.primary as dhcp_primary,
                    gds.type as dhcp_type,
                    gds.secondary_ip as dhcp_secondary_ip,
                    gds.secondary as dhcp_secondary,
                    gds2.name as did_we_join
                from
                    gmi_sites
                left join cp_region on gmi_sites.region=cp_region.id
                left join global_dhcp_server as gds2 on gds2.site=gmi_sites.site
                left join global_dhcp_server as gds on gds.site=(CASE when gmi_sites.dhcp_override is not null and trim(dhcp_override) <> "" then gmi_sites.dhcp_override when gds2.name is
                null then cp_region.hub_code else gmi_sites.site end)
                where
                    gds.type={}
                    and gmi_sites.site='{}';
            """.format(dhcp_type2, site.upper())
    s.query(query)
    return (jsonify(s.getAllRows()))

@app.route("/rest/v1/gmi-latency", methods=['GET'])
@app.route("/rest/v1/gmi-latency/<site>", methods=['GET'])
def gmi_latency(site=None):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    if (site==None):
	    query = "select sc.*,sl.description,DATEDIFF(now(),STR_TO_DATE(stamp,'%a %b %e %H:%i:%s %Y')) as delta from sla_collection sc, sla_locations sl where sc.device=sl.core order by sl.description, sla_id;"
    else:
        query = """select sc.*, sl.description,
        DATEDIFF(now(),STR_TO_DATE(stamp,'%a %b %e %H:%i:%s %Y')) as delta from
        sla_collection sc, sla_locations sl where sc.device=sl.core and
        left(sl.core,locate('-',sl.core)-1)='{}' order by
        sl.description, sla_id""".format(site.upper())
    s.query(query)
    return ({ "result" : s.getAllRows() })

@app.route("/rest/v1/gmi-sites", methods=['GET'])
@app.route("/rest/v1/gmi-sites/<site>", methods=['GET'])
def gmi_site(site=None):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    if (site==None):
        query = "select site,equipment,type,city,state,country,nickname from gmi_sites order by site;"
    else:
        query = """select site,equipment,type,city,state,country,nickname from
        gmi_sites where site='{}'""".format(site)
    s.query(query)
    return ({ "result" : s.getAllRows() })

@app.route("/rest/v1/gmi-core", methods=['GET'])
@app.route("/rest/v1/gmi-core/<core>", methods=['GET'])
@login_required
def gmi_core(core=None):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    if (core==None):
        query = "select core,description,asNum from sla_locations order by core;"
    else:
        query = "select core,description,asNum from sla_locations where core='{}';".format(core)
    s.query(query)
    return ({ "result" : s.getAllRows() })

@app.route('/images/<path:path>')
def serve_images(path):
    try:
        return send_from_directory('/images', path)
    except Exception as e:
        return send_from_directory('/app/images', path)

@app.route('/css/<path:path>')
def serve_css(path):
    try:
        return send_from_directory('/css', path)
    except Exception as e:
        return send_from_directory('/app/css', path)

@app.route('/js/<path:path>')
def serve_js(path):
    try:
        return send_from_directory('/js', path)
    except Exception as e:
        return send_from_directory('/app/js', path)

@app.route("/rest/v1/gmi-sites-geo", methods=['GET'])
@app.route("/rest/v1/gmi-sites-geo/<site>", methods=['GET'])
def gmi_site_geo(site=None):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    if (site==None):
        query = "select gs.site,gs.equipment,gs.type,gs.city,gs.state,gs.country,gs.nickname,ss.lat,ss.lng from gmi_sites gs, samurai_sites ss where gs.site=ss.location and ss.lng is not null and ss.lat is not null order by gs.site;"
    else:
        query = """select gs.site, gs.equipment, gs.type, gs.city, gs.state,
        gs.country, gs.nickname, ss.lat, ss.lng from gmi_sites gs, samurai_sites
        ss where gs.site=ss.location and ss.lng is not null and ss.lat is not
        null and gs.site='{}'""".format(site)
    s.query(query)
    return ({ "result" : s.getAllRows() })

@app.route("/rest/v1/config/switch/<switch>/", methods=['GET'])
@login_required
def get_config_switch(switch=None):
    if (switch):
        #connection = ArubaCX("m1is574", LDAP_BIND_PASS, switch+".genmills.com")
        connection = ArubaCX("admin", ADMIN_PASS, "146.217.100.99")
        result = connection.get_running_config()
        return ("<pre>"+json.dumps({ "result" : result
            },indent=2).replace(" ","&nbsp;").replace("\n","<BR>\n")+"</pre>")
#        return({ "result" : result })
    else:
        return ({ "result" : "error" })

@app.route("/rest/v1/config/switch/<switch>/vlans", methods=['GET'])
@app.route("/rest/v1/config/switch/<switch>/vlans/<vlan>", methods=['GET'])
@login_required
def get_vlans(switch, vlan="", switchType="ArubaOS"):
    if (switch):
        if switchType =="ArubaOS":
            try:
                if K8_ENV:
                    k8_vlan_payload = {
                        "program-type": "import-legacy-vlans",
                        "inner-payload": {"switch_name": switch}
                    }
                    response = requests.post(API_SWAGGER_HOST+"/api/v1/uauth-post-to-pubsub",
                                             json=k8_vlan_payload,
                                             headers={'Content-Type': 'application/json'},
                                             verify=False)
                    assert response.status_code == 200
                    syslog.info("K8 VLAN TRIGGERED TO PUBSUB")
                    return jsonify({"POSTED": "OK"})
                else:
                    sw = ArubaOS("m1is574", LDAP_BIND_PASS, switch, debug=False)
                    try:
                        sw.login()
                    except Exception as e:
                        return (e)
                    if sw.isLoggedIn():
                        return (sw.get_vlans())
            except Exception as e:
                syslog.error("ERROR: {}".format(e))
                return (e)

@app.route("/rest/v1/config/vlanswebhook", methods=['POST'])
def legacy_vlans_webhook():
    try:
        data = request.json
        syslog.info("DATA: {}".format(data))
        redis_cache.set(data['switch_name'], json.dumps(data['vlan_data']))
        return jsonify({"Data saved to redis": "OK"})
    except Exception as e:
        syslog.error("ERROR: {}".format(e))
        return (e) 

@app.route("/rest/v1/config/fetchvlans/<switch>", methods=['GET'])
def legacy_vlans_results(switch):
    try:
        vlan_data = redis_cache.get(switch)
        syslog.info("VLAN DATA: {}".format(vlan_data))
        if vlan_data:
            return jsonify({"result_vlan": json.loads(vlan_data)}), 200
        return jsonify({"result_vlan": []}), 200
    except Exception as e:
        return (e) 

### API for INTERFACE SPANNING-TREE
@app.route("/rest/v1/config/ip/spantree", methods=['GET'])
@login_required
def get_ip_spantree():
    all = switch_spantree_policy.query.all()
    results = switch_spantree_policies_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/ip/spantree", methods=['POST'])
@login_required
def add_ip_spantree():
    name = request.json['name']
    spantree = request.json['spantree']
    spantree_cost = request.json['spantree_cost']
    spantree_port_priority = request.json['spantree_port_priority']
    spantree_port_type = request.json['spantree_port_type']
    spantree_link_type = request.json['spantree_link_type']
    spantree_tcn_guard = request.json['spantree_tcn_guard']
    record = switch_spantree_policy(name, spantree, spantree_cost,
            spantree_port_priority, spantree_port_type, spantree_link_type,
            spantree_tcn_guard)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_spantree_policy_schema.jsonify(record)

@app.route("/rest/v1/config/ip/spantree/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_ip_spantree(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_spantree_policy.query.get(id)
        if 'name' in update:
            record.name=request.json['name']
        if 'spantree' in update:
            record.spantree=request.json['spantree']
        if 'spantree_cost' in update:
            record.spantree_cost=request.json['spantree_cost']
        if 'spantree_link_type' in update:
            record.spantree_link_type=request.json['spantree_link_type']
        if 'spantree_port_priority' in update:
            record.spantree_port_priority=request.json['spantree_port_priority']
        if 'spantree_port_type' in update:
            record.spantree_port_type=request.json['spantree_port_type']
        if 'spantree_tcn_guard' in update:
            record.spantree_tcn_guard=request.json['spantree_tcn_guard']
        sdb.session.commit()
        return switch_spantree_policy_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_spantree_policy.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_spantree_policy_schema.jsonify(record)

### API for INTERFACE LLDP
@app.route("/rest/v1/config/ip/lldp", methods=['GET'])
@login_required
def get_ip_lldp():
    all = switch_lldp_policy.query.all()
    results = switch_lldp_policies_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/ip/lldp", methods=['POST'])
@login_required
def add_ip_lldp():
    name = request.json['name']
    transmit = request.json['transmit']
    receive = request.json['recieve']
    trap_enable = request.json['trap_enable']
    dot3_macphy = request.json['dot3_macphy']
    dot3_poe = request.json['dot3_poe']
    med_poe = request.json['med_poe']
    med_poe_priority_override = request.json['med_poe_priority_override']
    med = request.json['med']
    med_location_civ_addr = request.json['med_location_civ_addr']
    med_location_civ_switch = request.json['med_location_civ_switch']
    med_location_civ_desc = request.json['med_location_civ_desc']
    med_location_elin = request.json['med_location_elin']
    cdp_mode = request.json['cdp_mode']
    record = switch_lldp_policy(name, transmit, receive, trap_enable,
            dot3_macphy, dot3_poe, med_poe, med_poe_priority_override, med,
            med_location_civ_addr, med_location_civ_switch,
            med_location_civ_desc, med_location_elin, cdp_mode)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_lldp_policy_schema.jsonify(record)

@app.route("/rest/v1/config/ip/lldp/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_ip_lldp(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_lldp_policy.query.get(id)
        if 'id' in update:
            record.id=request.json['id']
        if 'name' in update:
            record.name=request.json['name']
        if 'transmit' in update:
            record.transmit=request.json['transmit']
        if 'receive' in update:
            record.receive=request.json['receive']
        if 'trap_enable' in update:
            record.trap_enable=request.json['trap_enable']
        if 'dot3_macphy' in update:
            record.dot3_macphy=request.json['dot3_macphy']
        if 'dot3_poe' in update:
            record.dot3_poe=request.json['dot3_poe']
        if 'med_poe' in update:
            record.med_poe=request.json['med_poe']
        if 'med_poe_priority_override' in update:
            record.med_poe_priority_override=request.json['med_poe_priority_override']
        if 'med' in update:
            record.med=request.json['med']
        if 'med_location_civ_addr' in update:
            record.med_location_civ_addr=request.json['med_location_civ_addr']
        if 'med_location_civ_switch' in update:
            record.med_location_civ_switch=request.json['med_location_civ_switch']
        if 'med_location_civ_desc' in update:
            record.med_location_civ_desc=request.json['med_location_civ_desc']
        if 'med_location_elin' in update:
            record.med_location_elin=request.json['med_location_elin']
        if 'cdp_mode' in update:
            record.cdp_mode=request.json['cdp_mode']
        sdb.session.commit()
        return switch_lldp_policy_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_lldp_policy.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_lldp_policy_schema.jsonify(record)

### API for INTERFACE ROLE
@app.route("/rest/v1/config/ip/role", methods=['GET'])
@login_required
def get_ip_role():
    all = switch_port_role_profile.query.all()
    results = switch_role_policies_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/ip/role", methods=['POST'])
@login_required
def add_ip_role():
    aaa_auth_client_limit_multi=request.json['aaa_auth_client_limit_multi']
    aaa_auth_dot1x_discovery_period=request.json['aaa_auth_dot1x_discovery_period']
    aaa_auth_dot1x_eapol_timeout=request.json['aaa_auth_dot1x_eapol_timeout']
    aaa_auth_dot1x_initial_response_timeout=request.json['aaa_auth_dot1x_initial_response_timeout']
    aaa_auth_dot1x_max_retries=request.json['aaa_auth_dot1x_max_retries']
    aaa_auth_dot1x_quiet=request.json['aaa_auth_dot1x_quiet']
    aaa_auth_mac_reauth=request.json['aaa_auth_mac_reauth']
    aaa_auth_mac_reauth_period=request.json['aaa_auth_mac_reauth_period']
    allow_cdp_auth=request.json['allow_cdp_auth']
    auth_mode=request.json['auth_mode']
    critical_voice_role=request.json['critical_voice_role']
    portaccess_device_profile=request.json['portaccess_device_profile']
    portaccess_fb_role=request.json['portaccess_fb_role']
    portaccesS_ob_method=request.json['portaccesS_ob_method']
    portaccess_ps_client_limit=request.json['portaccess_ps_client_limit']
    portaccess_security_violation=request.json['portaccess_security_violation']
    portaccess_security_violation_recovery=request.json['portaccess_security_violation_recovery']
    aaa_auth_client_limit=request.json['aaa_auth_client_limit']
    aaa_auth_dot1x_cached_reauth=request.json['aaa_auth_dot1x_cached_reauth']
    aaa_auth_dot1x_max_eapol=request.json['aaa_auth_dot1x_max_eapol']
    aaa_auth_dot1x_reauth_period=request.json['aaa_auth_dot1x_reauth_period']
    aaa_auth_mac=request.json['aaa_auth_mac']
    aaa_auth_mac_cached_reauth=request.json['aaa_auth_mac_cached_reauth']
    aaa_auth_mac_quiet=request.json['aaa_auth_mac_quiet']
    aaa_auth_precedence=request.json['aaa_auth_precedence']
    aaa_auth_priority=request.json['aaa_auth_priority']
    allow_cdp_bpdu=request.json['allow_cdp_bpdu']
    allow_flood_traffic=request.json['allow_flood_traffic']
    allow_lldp_auth=request.json['allow_lldp_auth']
    allow_lldp_bpdu=request.json['allow_lldp_bpdu']
    auth_role=request.json['auth_role']
    critical_role=request.json['critical_role']
    portaccess_device_profile_mode=request.json['portaccess_device_profile_mode']
    portaccess_ob_precedence=request.json['portaccess_ob_precedence']
    portaccess_ps=request.json['portaccess_ps']
    portaccess_ps_mac=request.json['portaccess_ps_mac']
    portaccess_security_violation_timer=request.json['portaccess_security_violation_timer']
    portfilter=request.json['portfilter']
    preauth_role=request.json['preauth_role']
    radio_override=request.json['radio_override']
    reject_role=request.json['reject_role']
    name=request.json['name']
    record = switch_port_role_profile(name, portaccess_ps, portaccess_ps_mac, portfilter,
            portaccess_fb_role, aaa_auth_precedence, portaccess_ob_precedence,
            portaccesS_ob_method, aaa_auth_priority,
            portaccess_security_violation, portaccess_security_violation_timer,
            portaccess_security_violation_recovery, critical_role,
            critical_voice_role, preauth_role, reject_role, auth_role,
            auth_mode, allow_lldp_bpdu, allow_cdp_bpdu, allow_lldp_auth,
            allow_cdp_auth, radio_override, allow_flood_traffic, aaa_auth_mac,
            aaa_auth_mac_reauth, aaa_auth_mac_cached_reauth,
            portaccess_device_profile, portaccess_device_profile_mode,
            portaccess_ps_client_limit, aaa_auth_client_limit,
            aaa_auth_client_limit_multi, aaa_auth_mac_quiet,
            aaa_auth_mac_reauth_period,
            aaa_auth_dot1x_quiet, aaa_auth_dot1x_cached_reauth,
            aaa_auth_dot1x_max_retries, aaa_auth_dot1x_reauth_period,
            aaa_auth_dot1x_discovery_period, aaa_auth_dot1x_max_eapol,
            aaa_auth_dot1x_eapol_timeout,
            aaa_auth_dot1x_initial_response_timeout)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_role_policy_schema.jsonify(record)

@app.route("/rest/v1/config/ip/role/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_ip_role(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_role_policy.query.get(id)
        if 'name' in update:
            record.name=request.json['name']
        if 'portaccess_ps' in update:
            record.portaccess_ps=request.json['portaccess_ps']
        if 'portaccess_ps_mac' in update:
            record.portaccess_ps_mac=request.json['portaccess_ps_mac']
        if 'portfilter' in update:
            record.portfilter=request.json['portfilter']
        if 'portaccess_fb_role' in update:
            record.portaccess_fb_role=request.json['portaccess_fb_role']
        if 'aaa_auth_precedence' in update:
            record.aaa_auth_precedence=request.json['aaa_auth_precedence']
        if 'portaccess_ob_precedence' in update:
            record.portaccess_ob_precedence=request.json['portaccess_ob_precedence']
        if 'portaccess_ob_method' in update:
            record.portaccess_ob_method=request.json['portaccess_ob_method']
        if 'aaa_auth_priority' in update:
            record.aaa_auth_priority=request.json['aaa_auth_priority']
        if 'portaccess_security_violation' in update:
            record.portaccess_security_violation=request.json['portaccess_security_violation']
        if 'portaccess_security_violation_timer' in update:
            record.portaccess_security_violation_timer=request.json['portaccess_security_violation_timer']
        if 'portaccess_security_violation_recovery' in update:
            record.portaccess_security_violation_recovery=request.json['portaccess_security_violation_recovery']
        if 'critical_role' in update:
            record.critical_role=request.json['critical_role']
        if 'critical_voice_role' in update:
            record.critical_voice_role=request.json['critical_voice_role']
        if 'preauth_role' in update:
            record.preauth_role=request.json['preauth_role']
        if 'reject_role' in update:
            record.reject_role=request.json['reject_role']
        if 'auth_role' in update:
            record.auth_role=request.json['auth_role']
        if 'auth_mode' in update:
            record.auth_mode=request.json['auth_mode']
        if 'allow_lldp_bpdu' in update:
            record.allow_lldp_bpdu=request.json['allow_lldp_bpdu']
        if 'allow_cdp_bpdu' in update:
            record.allow_cdp_bpdu=request.json['allow_cdp_bpdu']
        if 'allow_lldp_auth' in update:
            record.allow_lldp_auth=request.json['allow_lldp_auth']
        if 'allow_cdp_auth' in update:
            record.allow_cdp_auth=request.json['allow_cdp_auth']
        if 'radius_override' in update:
            record.radius_override=request.json['radius_override']
        if 'allow_flood_traffic' in update:
            record.allow_flood_traffic=request.json['allow_flood_traffic']
        if 'aaa_auth_mac' in update:
            record.aaa_auth_mac=request.json['aaa_auth_mac']
        if 'aaa_auth_mac_cached_reauth' in update:
            record.aaa_auth_mac_cached_reauth=request.json['aaa_auth_mac_cached_reauth']
        if 'aaa_auth_dot1x' in update:
            record.aaa_auth_dot1x=request.json['aaa_auth_dot1x']
        if 'portaccess_device_profile' in update:
            record.portaccess_device_profile=request.json['portaccess_device_profile']
        if 'portaccess_device_profile_mode' in update:
            record.portaccess_device_profile_mode=request.json['portaccess_device_profile_mode']
        if 'portaccess_ps_client_limit' in update:
            record.portaccess_ps_client_limit=request.json['portaccess_ps_client_limit']
        if 'aaa_auth_client_limit' in update:
            record.aaa_auth_client_limit=request.json['aaa_auth_client_limit']
        if 'aaa_auth_client_limit_multi' in update:
            record.aaa_auth_client_limit_multi=request.json['aaa_auth_client_limit_multi']
        if 'aaa_auth_mac_quiet' in update:
            record.aaa_auth_mac_quiet=request.json['aaa_auth_mac_quiet']
        if 'aaa_auth_mac_reauth' in update:
            record.aaa_auth_mac_reauth=request.json['aaa_auth_mac_reauth']
        if 'aaa_auth_mac_reauth_period' in update:
            record.aaa_auth_mac_reauth_period=request.json['aaa_auth_mac_reauth_period']
        if 'aaa_auth_dot1x_quiet' in update:
            record.aaa_auth_dot1x_quiet=request.json['aaa_auth_dot1x_quiet']
        if 'aaa_auth_dot1x_cached_reauth' in update:
            record.aaa_auth_dot1x_cached_reauth=request.json['aaa_auth_dot1x_cached_reauth']
        if 'aaa_auth_dot1x_max_retries' in update:
            record.aaa_auth_dot1x_max_retries=request.json['aaa_auth_dot1x_max_retries']
        if 'aaa_auth_dot1x_reauth_period' in update:
            record.aaa_auth_dot1x_reauth_period=request.json['aaa_auth_dot1x_reauth_period']
        if 'aaa_auth_dot1x_discovery_period' in update:
            record.aaa_auth_dot1x_discovery_period=request.json['aaa_auth_dot1x_discovery_period']
        if 'aaa_auth_dot1x_max_eapol' in update:
            record.aaa_auth_dot1x_max_eapol=request.json['aaa_auth_dot1x_max_eapol']
        if 'aaa_auth_dot1x_eapol_timeout' in update:
            record.aaa_auth_dot1x_eapol_timeout=request.json['aaa_auth_dot1x_eapol_timeout']
        if 'aaa_auth_dot1x_initial_response_timeout' in update:
            record.aaa_auth_dot1x_initial_response_timeout=request.json['aaa_auth_dot1x_initial_response_timeout']
        sdb.session.commit()
        return switch_role_policy_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_role_policy.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_role_policy_schema.jsonify(record)

### API for INTERFACE ACL
@app.route("/rest/v1/config/ip/acl", methods=['GET'])
@login_required
def get_ip_acl():
    all = switch_acl_policy.query.all()
    results = switch_acl_policies_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/ip/acl", methods=['POST'])
@login_required
def add_ip_acl():
    switch_acl_policy_name=request.json['switch_acl_policy_name']
    acl_in_ip=request.json['acl_in_ip']
    acl_in_mac=request.json['acl_in_mac']
    acl_out_ip=request.json['acl_out_ip']
    acl_out_mac=request.json['acl_out_mac']
    record = switch_acl_policy(switch_acl_policy_name, acl_in_ip, acl_out_ip,
            acl_in_mac, acl_out_mac)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_acl_policy_schema.jsonify(record)

@app.route("/rest/v1/config/ip/acl/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_ip_acl(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_role_acl.query.get(id)
        if 'switch_acl_policy_name' in update:
            record.switch_acl_policy_name=request.json['switch_acl_policy_name']
        if 'acl_in_ip' in update:
            record.acl_in_ip=request.json['acl_in_ip']
        if 'acl_out_ip' in update:
            record.acl_out_ip=request.json['acl_out_ip']
        if 'acl_in_mac' in update:
            record.acl_in_mac=request.json['acl_in_mac']
        if 'acl_out_mac' in update:
            record.acl_out_mac=request.json['acl_out_mac']
        sdb.session.commit()
        return switch_role_acl_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_role_acl.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_role_acl_schema.jsonify(record)

### API for INTERFACE PORT POLICY
@app.route("/rest/v1/config/ip/portsecurity", methods=['GET'])
@login_required
def get_ip_portpolicy():
    all = switch_port_policy.query.all()
    results = switch_port_policies_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/ip/portsecurity", methods=['POST'])
@login_required
def add_ip_portpolicy():
    pass

@app.route("/rest/v1/config/ip/portsecurity", methods=["PUT", "DELETE"])
@login_required
def modify_ip_portpolicy():
    pass

### API for INTERFACE QOS
@app.route("/rest/v1/config/ip/qos", methods=['GET'])
@login_required
def get_ip_qos():
    all = switch_qos_policy.query.all()
    results = switch_qos_policies_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/ip/qos", methods=['POST'])
@login_required
def add_ip_qos():
    name=request.json['name']
    cos=request.json['cos']
    rate_limit_type=request.json['rate_limit_type']
    rate_limit_value_type=request.json['rate_limit_value_type']
    apply_policy_name=request.json['apply_policy_name']
    rate_limit_subtype=request.json['rate_limit_subtype']
    qos_shape=request.json['qos_shape']
    trust=request.json['trust']
    rate_limit_value=request.json['rate_limit_value']
    set_dscp=request.json['set_dscp']
    record = switch_qos_policy(name, cos, apply_policy_name, trust, set_dscp,
            rate_limit_type, rate_limit_subtype, rate_limit_value,
            rate_limit_value_type, qos_shape)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_qos_policy_schema.jsonify(record)

@app.route("/rest/v1/config/ip/qos/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_ip_qos(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_qos_policy.query.get(id)
        if 'name' in update:
            record.name=request.json['name']
        if 'cos' in update:
            record.cos=request.json['cos']
        if 'apply_policy_name' in update:
            record.apply_policy_name=request.json['apply_policy_name']
        if 'trust' in update:
            record.trust=request.json['trust']
        if 'set_dscp' in update:
            record.set_dscp=request.json['set_dscp']
        if 'rate_limit_type' in update:
            record.rate_limit_type=request.json['rate_limit_type']
        if 'rate_limit_subtype' in update:
            record.rate_limit_subtype=request.json['rate_limit_subtype']
        if 'rate_limit_value' in update:
            record.rate_limit_value=request.json['rate_limit_value']
        if 'rate_limit_value_type' in update:
            record.rate_limit_value_type=request.json['rate_limit_value_type']
        if 'qos_shape' in update:
            record.qos_shape=request.json['qos_shape']
        sdb.session.commit()
        return switch_qos_policy_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_qos_policy.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_qos_policy_schema.jsonify(record)

### API for INTERFACE IGMP
@app.route("/rest/v1/config/ip/igmp", methods=['GET'])
@login_required
def get_ip_igmp():
    all = switch_igmp_policy.query.all()
    results = switch_igmp_policies_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/ip/igmp", methods=['POST'])
@login_required
def add_ip_igmp():
    switch_igmp_policy_name=request.json['switch_igmp_policy_name']
    version=request.json['version']
    strict=request.json['strict']
    querier=request.json['querier']
    robustness=request.json['robustness']
    last_member_query_interval=request.json['last_member_query_interval']
    query_max_response_time=request.json['query_max_response_time']
    static_group=request.json['static_group']
    access_list=request.json['access_list']
    router_alert_check=request.json['router_alert_check']
    snooping_forward_vlan=request.json['snooping_forward_vlan']
    snooping_blocked_vlan=request.json['snooping_blocked_vlan']
    snooping_auto_vlan=request.json['snooping_auto_vlan']
    snooping_fastleave_vlan=request.json['snooping_fastleave_vlan']
    snooping_frced_fastleave_vlan=request.json['snooping_frced_fastleave_vlan']
    record = switch_igmp_policy(switch_igmp_policy_name, version, strict, querier, robustness, last_member_query_interval, query_max_response_time, static_group, access_list, router_alert_check, snooping_forward_vlan, snooping_blocked_vlan, snooping_auto_vlan, snooping_fastleave_vlan, snooping_frced_fastleave_vlan)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_igmp_policy_schema.jsonify(record)

@app.route("/rest/v1/config/ip/igmp/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_ip_igmp(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_igmp_policy.query.get(id)
        if 'switch_igmp_policy_name' in update:
            record.switch_igmp_policy_name=request.json['switch_igmp_policy_name']
        if 'version' in update:
            record.version=request.json['version']
        if 'strict' in update:
            record.strict=request.json['strict']
        if 'querier' in update:
            record.querier=request.json['querier']
        if 'robustness' in update:
            record.robustness=request.json['robustness']
        if 'last_member_query_interval' in update:
            record.last_member_query_interval=request.json['last_member_query_interval']
        if 'query_max_response_time' in update:
            record.query_max_response_time=request.json['query_max_response_time']
        if 'static_group' in update:
            record.static_group=request.json['static_group']
        if 'access_list' in update:
            record.access_list=request.json['access_list']
        if 'router_alert_check' in update:
            record.router_alert_check=request.json['router_alert_check']
        if 'snooping_forward_vlan' in update:
            record.snooping_forward_vlan=request.json['snooping_forward_vlan']
        if 'snooping_blocked_vlan' in update:
            record.snooping_blocked_vlan=request.json['snooping_blocked_vlan']
        if 'snooping_auto_vlan' in update:
            record.snooping_auto_vlan=request.json['snooping_auto_vlan']
        if 'snooping_fastleave_vlan' in update:
            record.snooping_fastleave_vlan=request.json['snooping_fastleave_vlan']
        if 'snooping_forced_fastleave_vlan' in update:
            record.snooping_forced_fastleave_vlan=request.json['snooping_forced_fastleave_vlan']
        sdb.session.commit()
        return switch_igmp_policy_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_igmp_policy.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_igmp_policy_schema.jsonify(record)

############################################################ switch lags #####
@app.route("/rest/v1/config/ip/trunklag", methods=['GET'])
@app.route("/rest/v1/config/ip/trunklag/<switch_name>", methods=['GET'])
@app.route("/rest/v1/config/ip/trunklag/<switch_name>/<id>", methods=['GET'])
@login_required
def get_trunklag(switch_name="",id=""):
    if (switch_name == ""):
        all = switch_trunk_lag.query.all()
    else:
        if (id != ""):
            all = switch_trunk_lag.query.filter_by(id=id).all()
        else:
            all = switch_trunk_lag.query.filter_by(switch_name=switch_name).all()
    r = len(all)
    for i in range(0,r):
        all[i].allowed = vlans_to_list(vlans_from_bytes(all[i].allowed))
    results = switch_trunks_lags_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/ip/trunklag", methods=['POST','PUT'])
@login_required
def add_trunklag():
    switch_name=request.json['switch_name']
    is_lag=request.json['is_lag']
    entity_id=request.json['entity_id']
    entity_id_sub=request.json['entity_id_sub']
    native=request.json['native_vlan']
    native_tag=request.json['native_tag']
    allowed=vlans_to_bytes(vlans_from_list(request.json['allowed']))
    lacp=request.json['lacp']
    lacp_rate=request.json['lacp_rate']
    description = request.json['description']
    record = switch_trunk_lag(switch_name, is_lag, entity_id, entity_id_sub,
            native, native_tag, allowed,
                        lacp, lacp_rate, description)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_trunk_lag_schema.jsonify(record)

@app.route("/rest/v1/config/ip/trunklag/<id>", methods=["DELETE","PUT"])
@app.route("/rest/v1/config/ip/trunklag/<id>/<entity>", methods=["PUT"])
@app.route("/rest/v1/config/ip/trunklag/<id>/<entity>/<sub>", methods=["PUT"])
@login_required
def modify_trunklag(id, entity="", sub=0):
    if request.method=="PUT":
        update = request.json.keys()
        if request.url_rule.rule == "/rest/v1/config/ip/trunklag/<id>/<entity>" or request.url_rule.rule == "/rest/v1/config/ip/trunklag/<id></entity>/<sub>":
            record = switch_trunk_lag.query.filter_by(switch_name=id, entity_id=int(entity), entity_id_sub=int(sub), is_lag=request.json['is_lag']).first()
            record.entity_id=entity
            record.entity_id_sub=sub
            record.switch_name=id
        else:
            record = switch_trunk_lag.query.get(id)
            if 'entity_id' in update:
                record.entity_id=request.json['entity_id']
            if 'entity_id_sub' in update:
                record.native=request.json['entity_id_sub']
        if 'is_lag' in update:
            record.is_lag=request.json['is_lag']
        if 'native_vlan' in update:
            record.native_vlan=request.json['native_vlan']
        if 'native_tag' in update:
            record.native_tag=request.json['native_tag']
        if 'allowed' in update:
            record.allowed=vlans_to_bytes(vlans_from_list(request.json['allowed']))
        if 'lacp' in update:
            record.lacp=request.json['lacp']
        if 'lacp_rate' in update:
            record.lacp_rate=request.json['lacp_rate']
        if 'description' in update:
            record.description=request.json['description']
        sdb.session.commit()
        result = record.to_dict()
        result["id"] = id
        result["allowed"] = vlans_to_list(vlans_from_bytes(result["allowed"]))
        syslog.info("{} --> MODIFIED TRUNK/LAG IN CONTROL CONFIG ({},{})".format(session["name"], id, result))
        return jsonify(result)
    if request.method=="DELETE":
        record = switch_trunk_lag.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        syslog.info("{} --> DELETED TRUNK/LAG FROM CONTROL CONFIG ({})".format(session["name"], id))
        return switch_trunk_lag_schema.jsonify(record)

############################################################ API for SWITCH PORT #####
@app.route("/rest/v1/config/switchinterface", methods=['GET'])
@app.route("/rest/v1/config/switchinterface/<switch_name>", methods=['GET'])
@app.route("/rest/v1/config/switchinterface/<switch_name>/<switch_number>", methods=['GET'])
@app.route("/rest/v1/config/switchinterface/<switch_name>/<switch_number>/<port>", methods=['GET'])
@app.route("/rest/v1/config/switchinterface/<switch_name>/<switch_number>/<port>/<sub_interface>", methods=['GET'])
@login_required
def get_switchinterface(switch_name="",switch_number=1,port=1,sub_interface=0):
    if request.url_rule.rule == "/rest/v1/config/switchinterface":
        all = switch_device_port.query.all()
        results = switch_device_ports_schema.dump(all)
        return jsonify(results)
    if request.url_rule.rule == "/rest/v1/config/switchinterface/<switch_name>":
        all = switch_device_port.query.filter_by(switch_name=switch_name).all()
        results = switch_device_ports_schema.dump(all)
        return jsonify(results)
    if request.url_rule.rule == "/rest/v1/config/switchinterface/<switch_name>/<switch_number>":
        all = switch_device_port.query.filter_by(switch_name=switch_name,
                switch_number=switch_number).all()
        results = switch_device_ports_schema.dump(all)
        return jsonify(results)
    if request.url_rule.rule == "/rest/v1/config/switchinterface/<switch_name>/<switch_number>/<port>":
        all = switch_device_port.query.filter_by(switch_name=switch_name,
                switch_number=switch_number, port=port, sub_interface=0).first()
        results = switch_device_port_schema.dump(all)
        return jsonify(results)
    if request.url_rule.rule == "/rest/v1/config/switchinterface/<switch_name>/<switch_number>/<port>/<sub_interface>":
        all = switch_device_port.query.filter_by(switch_name=switch_name,
                switch_number=switch_number, port=port,
                sub_interface=sub_interface).first()
        results = switch_device_port_schema.dump(all)
        return jsonify(results)

@app.route("/rest/v1/config/switchinterface", methods=['POST'])
@login_required
def add_switchinterface():
    acl_policy=request.json['acl_policy']
    arp_inspection=request.json['arp_inspection']
    arp_ip_local_proxy=request.json['arp_ip_local_proxy']
    arp_proxy=request.json['arp_proxy']
    arp_timeout=request.json['arp_timeout']
    bfd=request.json['bfd']
    client_track_ip=request.json['client_track_ip']
    client_track_ip_interval=request.json['client_track_ip_interval']
    description=request.json['description']
    dhcpv4_snooping=request.json['dhcpv4_snooping']
    flow_control=request.json['flow_control']
    igmp_policy=request.json['igmp_policy']
    ip=request.json['ip']
    ip_directed_broadcast=request.json['ip_directed_broadcast']
    ip_mtu=request.json['ip_mtu']
    ip_urpf_check=request.json['ip_urpf_check']
    ipv4_source_lockdown=request.json['ipv4_source_lockdown']
    l3_counters=request.json['l3_counters']
    lag=request.json['lag']
    lldp_policy=request.json['lldp_policy']
    loop_protect=request.json['loop_protect']
    loop_protect_action=request.json['loop_protect_action']
    mac_notify=request.json['mac_notify']
    mtu=request.json['mtu']
    nd_snooping=request.json['nd_snooping']
    poe=request.json['poe']
    poe_allocateby=request.json['poe_allocateby']
    poe_class=request.json['poe_class']
    poe_pdoverride=request.json['poe_pdoverride']
    poe_pre_std=request.json['poe_pre_std']
    poe_priority=request.json['poe_priority']
    port=request.json['port']
    port_security=request.json['port_security']
    port_security_profile=request.json['port_security_profile']
    qos_policy=request.json['qos_policy']
    routing=request.json['routing']
    sflow=request.json['sflow']
    shutdown=request.json['shutdown']
    spantree_profile=request.json['spantree_profile']
    speed=request.json['speed']
    sub_interface=request.json['sub_interface']
    switch_name=request.json['switch_name']
    switch_number=request.json['switch_number']
    switch_port_policy=request.json['switch_port_policy']
    track=request.json['track']
    trunk=request.json['trunk']
    udld=request.json['udld']
    vlan_access=request.json['vlan_access']
    vrf=request.json['vrf']
    vrrp=request.json['vrrp']
    record = switch_device_port()
    sdb.session.add(record)
    sdb.session.commit()
    return switch_device_port_schema.jsonify(record)

@app.route("/rest/v1/config/switchinterface/<switch_name>/<switch_number>/<port>", methods=["PUT", "DELETE"])
@app.route("/rest/v1/config/switchinterface/<switch_name>/<switch_number>/<port>/<sub_interface>", methods=["PUT", "DELETE"])
@login_required
def modify_interface(switch_name,switch_number,port,sub_interface=0):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_device_port.query.filter_by(switch_name=switch_name, switch_number=switch_number, port=port, sub_interface=sub_interface).first()
        if not record:
            record = switch_device_port(switch_name=switch_name,
                    switch_number=switch_number, port=port,
                    sub_interface=sub_interface, trunk=0, lag=0)
            sdb.session.add(record)
            sdb.session.commit()
        if 'acl_policy' in update:
            record.acl_policy=request.json['acl_policy']
        if 'arp_inspection' in update:
            record.arp_inspection=request.json['arp_inspection']
        if 'arp_ip_local_proxy' in update:
            record.arp_ip_local_proxy=request.json['arp_ip_local_proxy']
        if 'arp_proxy' in update:
            record.arp_proxy=request.json['arp_proxy']
        if 'arp_timeout' in update:
            record.arp_timeout=request.json['arp_timeout']
        if 'bfd' in update:
            record.bfd=request.json['bfd']
        if 'client_track_ip' in update:
            record.client_track_ip=request.json['client_track_ip']
        if 'client_track_ip_interval' in update:
            record.client_track_ip_interval=request.json['client_track_ip_interval']
        if 'description' in update:
            record.description=request.json['description']
        if 'dhcpv4_snooping' in update:
            record.dhcpv4_snooping=request.json['dhcpv4_snooping']
        if 'flow_control' in update:
            record.flow_control=request.json['flow_control']
        if 'igmp_policy' in update:
            record.igmp_policy=request.json['igmp_policy']
        if 'ip' in update:
            record.ip=request.json['ip']
        if 'ip_directed_broadcast' in update:
            record.ip_directed_broadcast=request.json['ip_directed_broadcast']
        if 'ip_mtu' in update:
            record.ip_mtu=request.json['ip_mtu']
        if 'ip_urpf_check' in update:
            record.ip_urpf_check=request.json['ip_urpf_check']
        if 'ipv4_source_lockdown' in update:
            record.ipv4_source_lockdown=request.json['ipv4_source_lockdown']
        if 'l3_counters' in update:
            record.l3_counters=request.json['l3_counters']
        if 'lag' in update:
            record.lag=request.json['lag']
        if 'lldp_policy' in update:
            record.lldp_policy=request.json['lldp_policy']
        if 'loop_protect' in update:
            record.loop_protect=request.json['loop_protect']
        if 'loop_protect_action' in update:
            record.loop_protect_action=request.json['loop_protect_action']
        if 'mac_notify' in update:
            record.mac_notify=request.json['mac_notify']
        if 'mtu' in update:
            record.mtu=request.json['mtu']
        if 'nd_snooping' in update:
            record.nd_snooping=request.json['nd_snooping']
        if 'poe' in update:
            record.poe=request.json['poe']
        if 'poe_allocateby' in update:
            record.poe_allocateby=request.json['poe_allocateby']
        if 'poe_class' in update:
            record.poe_class=request.json['poe_class']
        if 'poe_pdoverride' in update:
            record.poe_pdoverride=request.json['poe_pdoverride']
        if 'poe_pre_std' in update:
            record.poe_pre_std=request.json['poe_pre_std']
        if 'poe_priority' in update:
            record.poe_priority=request.json['poe_priority']
        if 'port_security' in update:
            record.port_security=request.json['port_security']
        if 'port_security_profile' in update:
            record.port_security_profile=request.json['port_security_profile']
        if 'qos_policy' in update:
            record.qos_policy=request.json['qos_policy']
        if 'routing' in update:
            record.routing=request.json['routing']
        if 'sflow' in update:
            record.sflow=request.json['sflow']
        if 'shutdown' in update:
            record.shutdown=request.json['shutdown']
        if 'spantree_profile' in update:
            record.spantree_profile=request.json['spantree_profile']
        if 'speed' in update:
            record.speed=request.json['speed']
        if 'sub_interface' in update:
            record.sub_interface=request.json['sub_interface']
        if 'switch_port_policy' in update:
            record.switch_port_policy=request.json['switch_port_policy']
        if 'track' in update:
            record.track=request.json['track']
        if 'trunk' in update:
            record.trunk=request.json['trunk']
        if 'udld' in update:
            record.udld=request.json['udld']
        if 'vlan_access' in update:
            record.vlan_access=request.json['vlan_access']
        if 'vrf' in update:
            record.vrf=request.json['vrf']
        if 'vrrp' in update:
            record.vrrp=request.json['vrrp']
        sdb.session.commit()
        #This 'sn' isn't correct for 6400 switches, but is only used in the syslog entry
        sn=int(switch_number)+1
        syslog.info("{} --> MODIFIED INTERFACE IN CONTROL CONFIG ({}, {}/{})".format(session["name"], switch_name, sn, port))
        return switch_device_port_schema.jsonify(record)
    if request.method=='DELETE':
        record = switch_device_port.query.filter_by(switch_name=switch_name, switch_number=switch_number, port=port, sub_interface=sub_interface).first()
        sdb.session.delete(record)
        sdb.session.commit()
        sn=int(switch_number)+1
        syslog.info("{} --> DELETED INTERFACE IN CONTROL CONFIG ({}, {}/{})".format(session["name"], switch_name, sn, port))
        return switch_device_port_schema.jsonify(record)

############################################################ API for CP_REGION  #####
@app.route("/rest/v1/config/cp/regions", methods=['GET'])
@login_required
def get_cp_regions():
    all = cp_region.query.all()
    results = cp_regions_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/cp/regions", methods=['POST'])
@login_required
def add_cp_regions():
    pass
#   _fields_ = json[_fields_]
#    record = _dbentity_(_fields_)
#    sdb.session.add(record)
#    sdb.session.commit()
#    return _schema.jsonify(record)

@app.route("/rest/v1/config/cp/regoins/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_cp_regions(id):
    if request.method=="PUT":
        pass
#        update = request.json.keys()
#        record = _dbentity.query.get(id)
#        _fields_ = json[_fields_]
#        sdb.session.commit()
#        return _schema.jsonify(record)

    if request.method=="DELETE":
        pass
#        record = _dbentity_.query.get(id)
#        sdb.session.delete(record)
#        sdb.session.commit()
#        return _schema.jsonify(record)

############################################################ API for CP_SITE_PROFILE #####
@app.route("/rest/v1/config/cp/siteprofile", methods=['GET'])
@app.route("/rest/v1/config/cp/siteprofile/<id>", methods=['GET'])
@app.route("/rest/v1/config/cp/siteprofile/region/<id>", methods=['GET'])
@login_required
def get_cp_siteprofile(id=""):
    if request.url_rule.rule=="/rest/v1/config/cp/siteprofile":
        all = cp_site_profile.query.all()
        results = cp_site_profiles_schema.dump(all)
        return jsonify(results)
    if request.url_rule.rule=="/rest/v1/config/cp/siteprofile/<id>":
        all = cp_site_profile.query.filter_by(site=id).first()
        results = cp_site_profile_schema.dump(all)
        return jsonify(results)
    if request.url_rule.rule=="/rest/v1/config/cp/siteprofile/region/<id>":
        all = cp_site_profile.query.filter_by(region=id).all()
        results = cp_site_profiles_schema.dump(all)
        return jsonify(results)

@app.route("/rest/v1/config/siteprofile", methods=['POST'])
@login_required
def add_cp_siteprofile():
    pass
#   _fields_ = json[_fields_]
#    record = _dbentity_(_fields_)
#    sdb.session.add(record)
#    sdb.session.commit()
#    return _schema.jsonify(record)

@app.route("/rest/v1/config/siteprofile/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_cp_siteprofile(id):
    if request.method=="PUT":
        pass
#        update = request.json.keys()
#        record = _dbentity.query.get(id)
#        _fields_ = json[_fields_]
#        sdb.session.commit()
#        return _schema.jsonify(record)

    if request.method=="DELETE":
        pass
#        record = _dbentity_.query.get(id)
#        sdb.session.delete(record)
#        sdb.session.commit()
#        return _schema.jsonify(record)

##################################################### API for SWITCH ROUTES #####
@app.route("/rest/v1/config/switchroutes", methods=['GET'])
@app.route("/rest/v1/config/switchroutes/<switch_name>", methods=['GET'])
@app.route("/rest/v1/config/switchroutes/<switch_name>/<id>", methods=['GET'])
@login_required
def get_switchroutes(switch_name="",id=""):
    if switch_name=="":
        all = switch_route.query.all()
        results = switch_routes_schema.dump(all)
    elif switch_name!="" and id=="":
        all = switch_route.query.filter_by(switch_name=switch_name).all()
        results = switch_routes_schema.dump(all)
    else:
        all = switch_route.query.get(id)
        results = switch_route_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/switchroutes", methods=['POST'])
@login_required
def add_switchroutes():
    switch_name=request.json['switch_name']
    ip_route=request.json['ip_route']
    ip_nexthop=request.json['ip_nexthop']
    outgoing_interface=request.json['outgoing_interface']
    blackhole=request.json['blackhole']
    reject=request.json['reject']
    tag=request.json['tag']
    distance=request.json['distance']
    vrf=request.json['vrf']
    description=request.json['description']
    bfd=request.json['bfd']
    record = switch_route(switch_name, ip_route, ip_nexthop, outgoing_interface,
            blackhole, reject, tag, distance, vrf, description,bfd)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_route_schema.jsonify(record)

@app.route("/rest/v1/config/switchroutes/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_switchroutes(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_route.query.get(id)
        if 'switch_name' in update:
            record.switch_name=request.json['switch_name']
        if 'ip_route' in update:
            record.ip_route=request.json['ip_route']
        if 'ip_nexthop' in update:
            record.ip_nexthop=request.json['ip_nexthop']
        if 'outgoing_interface' in update:
            record.outgoing_interface=request.json['outgoing_interface']
        if 'blackhole' in update:
            record.blackhole=request.json['blackhole']
        if 'reject' in update:
            record.reject=request.json['reject']
        if 'tag' in update:
            record.tag=request.json['tag']
        if 'distance' in update:
            record.distance=request.json['distance']
        if 'vrf' in update:
            record.vrf=request.json['vrf']
        if 'description' in update:
            record.description=request.json['description']
        if 'bfd' in update:
            record.bfd=request.json['bfd']
        sdb.session.commit()
        return switch_route_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_route.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_route_schema.jsonify(record)


############################################################ API for SWITCH FAMILY ####
@app.route("/rest/v1/config/switchFamily/<switch_name>", methods=['GET'])
@login_required
def get_switch_family(switch_name=""):
    if switch_name != "":
        records = site_switches.query.order_by(site_switches.switch_number.desc()).filter_by(switch_name=switch_name).first()
        data = records.serialize()
        return jsonify({"family": data["family"], "count":data["switch_number"]})
    else:
        return jsonify({"family":"error"})
############################################################ END API FOR SWITCH FAMILY ####

############################################################ API for SWITCH MGMT  #####
@app.route("/rest/v1/config/switchmgmt", methods=['GET'])
@app.route("/rest/v1/config/switchmgmt/<switch_name>", methods=['GET'])
@login_required
def get_switch_mgmt(switch_name=""):
    if switch_name == "":
        all = switch_mgmt.query.all()
        results = switches_mgmt_schema.dump(all)
        return jsonify(results)
    else:
        all = switch_mgmt.query.filter_by(switch_name=switch_name).first()
        results = switch_mgmt_schema.dump(all)
        return jsonify(results)

@app.route("/rest/v1/config/switchmgmt", methods=['POST'])
@login_required
def add_switch_mgmt():
    switch_name=request.json['switch_name']
    ip_dhcp=request.json['ip_dhcp']
    ip_static=request.json['ip_static']
    default_gateway=request.json['default_gateway']
    nameserver1=request.json['nameserver1']
    nameserver2=request.json['nameserver2']
    shutdown=request.json['shutdown']
    lldp_transmit=request.json['lldp_transmit']
    lldp_receive=request.json['lldp_receive']
    lldp_trap=request.json['lldp_trap']
    record = switch_mgmt(switch_name, ip_dhcp, ip_static, default_gateway, nameserver1, nameserver2, shutdown, lldp_transmit, lldp_receive, lldp_trap)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_mgmt_schema.jsonify(record)

@app.route("/rest/v1/config/switchmgmt/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_switch_mgmt(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_mgmt.query.get(id)
        if "switch_name" in update:
            record.switch_name=request.json['switch_name']
        if "ip_dhcp" in update:
            record.ip_dhcp=request.json['ip_dhcp']
        if "ip_static" in update:
            record.ip_static=request.json['ip_static']
        if "default_gateway" in update:
            record.default_gateway=request.json['default_gateway']
        if "nameserver1" in update:
            record.nameserver1=request.json['nameserver1']
        if "nameserver2" in update:
            record.nameserver2=request.json['nameserver2']
        if "shutdown" in update:
            record.shutdown=request.json['shutdown']
        if "lldp_transmit" in update:
            record.lldp_transmit=request.json['lldp_transmit']
        if "lldp_receive" in update:
            record.lldp_receive=request.json['lldp_receive']
        if "lldp_trap" in update:
            record.lldp_trap=request.json['lldp_trap']
        sdb.session.commit()
        return switch_mgmt_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_mgmt.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_mgmt_schema.jsonify(record)

############################################### API for SWITCH DEVICE MULTI VARS #####
@app.route("/rest/v1/config/switchDeviceMultiVar", methods=['GET'])
@app.route("/rest/v1/config/switchDeviceMultiVar/<switch_name>", methods=['GET'])
@app.route("/rest/v1/config/switchDeviceMultiVar/<switch_name>/<name>", methods=['GET'])
@login_required
def get_switch_device_multi_vars(switch_name="", name=""):
    if switch_name=="":
        all = switch_device_multi_vars.query.all()
    elif switch_name != "" and name != "":
        all = switch_device_multi_vars.query.filter_by(switch_name=switch_name, name=name).all()
    else:
        all = switch_device_multi_vars.query.filter_by(switch_name=switch_name).all()
    results = switch_device_multi_vars_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/switchDeviceMultiVar/<switch_name>/<name>", methods=['POST'])
@login_required
def add_switch_device_multi_vars(switch_name, name):
    description=request.json['description']
    value=request.json['value']
    record = switch_device_multi_vars(switch_name, name, description, value)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_device_multi_var_schema.jsonify(record)

@app.route("/rest/v1/config/switchDeviceMultiVar/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_switch_device_multi_vars(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_device_multi_vars.query.get(id)
        if "switch_name" in update:
            record.switch_name=request.json['switch_name']
        if "name" in update:
            record.name=request.json['name']
        if "description" in update:
            record.description=request.json['description']
        if "value" in update:
            record.value=request.json['value']
        sdb.session.commit()
        return switch_device_multi_var_schema.jsonify(record)
    if request.method=="DELETE":
        record = switch_device_multi_vars.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_device_multi_var_schema.jsonify(record)

############################################################ API for SWITCH MIRROR ENDPOINT #####
@app.route("/rest/v1/config/switchMirrorEndpoint", methods=['GET'])
@app.route("/rest/v1/config/switchMirrorEndpoint/<switch_name>", methods=['GET'])
@login_required
def get_switch_mirror_endpoint(switch_name=""):
    if switch_name=="":
        all = switch_mirror_endpoint.query.all()
    else:
        all = switch_mirror_endpoint.query.filter_by(switch_name=switch_name).all()
    r = len(all)
    for i in range(0,r):
        if all[i].destination:
            all[i].destination = mirror_to_list(mirror_from_bytes(all[i].destination))
    results = switch_mirror_endpoints_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/switchMirrorEndpoint", methods=['POST'])
@login_required
def add_switch_mirror_endpoint():
    switch_name=request.json['switch_name']
    endpoint=request.json['endpoint']
    mirror_source_ip=request.json['mirror_source_ip']
    mirror_dest_ip=request.json['mirror_dest_ip']
    vrf=request.json['vrf']
    enable=request.json['enable']
    comment=request.json['comment']
    destination=request.json['destination']
    destination=mirror_to_bytes(mirror_from_list(["{}/1/{}".format(k.split(":")[0],k.split(":")[1]) for k in destination]))
    record = switch_mirror_endpoint(switch_name, endpoint, mirror_source_ip, mirror_dest_ip, vrf, enable, comment, destination)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_mirror_endpoint_schema.jsonify(record)

@app.route("/rest/v1/config/switchMirrorEndpoint/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_switch_mirror_endpoint(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_mirror_endpoint.query.get(id)
        if 'switch_name' in update:
            record.switch_name=request.json['switch_name']
        if 'endpoint' in update:
            record.endpoint=request.json['endpoint']
        if 'mirror_source_ip' in update:
            record.mirror_source_ip=request.json['mirror_source_ip']
        if 'mirror_dest_ip' in update:
            record.mirror_dest_ip=request.json['mirror_dest_ip']
        if 'vrf' in update:
            record.vrf=request.json['vrf']
        if 'enable' in update:
            record.enable=request.json['enable']
        if 'comment' in update:
            record.comment=request.json['comment']
        if 'destination' in update:
            destination=request.json['destination']
            record.destination=mirror_to_bytes(mirror_from_list(destination))
            #.encode('utf-8')
        sdb.session.commit()
        return switch_mirror_endpoint_schema.jsonify(record)

    if request.method=="DELETE":
        record = switch_mirror_endpoint.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_mirror_endpoint_schema.jsonify(record)
################################################################# END SWITCH MIRROR ENDPOINT  #####

############################################################ API for SWITCH MIRROR SESSION  #####
@app.route("/rest/v1/config/switchMirrorSession", methods=['GET'])
@app.route("/rest/v1/config/switchMirrorSession/<switch_name>", methods=['GET'])
@login_required
def get_switch_mirror_session(switch_name=""):
    if switch_name == "":
        all = switch_mirror_session.query.order_by(switch_mirror_session.switch_name.asc(),switch_mirror_session.session.asc()).all()
    else:
        all = switch_mirror_session.query.filter_by(switch_name=switch_name).order_by(switch_mirror_session.session.asc()).all()
    r = len(all)
    for i in range(0,r):
        if all[i].source_interface:
            all[i].source_interface = mirror_to_list(mirror_from_bytes(all[i].source_interface))
        if all[i].source_interface_direction:
            all[i].source_interface_direction = rxtx_to_list(rxtx_from_bytes(all[i].source_interface_direction))
        if all[i].source_lag:
            all[i].source_lag = lag_to_list(lag_from_bytes(all[i].source_lag))
        if all[i].source_lag_direction:
            all[i].source_lag_direction = rxtx_to_list(rxtx_from_bytes(all[i].source_lag_direction))
        if all[i].source_vlan:
            all[i].source_vlan = vlans_to_list(vlans_from_bytes(all[i].source_vlan))
        if all[i].source_vlan_direction:
            all[i].source_vlan_direction = rxtx_to_list(rxtx_from_bytes(all[i].source_vlan_direction))
        if all[i].destination:
            all[i].destination = mirror_to_list(mirror_from_bytes(all[i].destination)) 
    results = switch_mirror_sessions_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/switchMirrorSession", methods=['POST'])
@login_required
def add_switch_mirror_session():
    switch_name=request.json['switch_name']
    session=request.json['session']
    comment=request.json['comment']
    enable=request.json['enable']

    source_interface=request.json['source_interface']
    print (source_interface)
    source_interface_direction=[]
    for k in source_interface:
        si = (int(k.split(":")[0])-1)*64+int(k.split(":")[1])
        sid = int(k.split(":")[2])
        source_interface_direction.append([si,sid])
    source_interface_direction=rxtx_to_bytes(rxtx_from_list(source_interface_direction,size=640))
    source_interface=mirror_to_bytes(mirror_from_list(["{}/1/{}".format(k.split(":")[0],k.split(":")[1]) for k in source_interface]))
    print (source_interface)
    print (source_interface_direction)

    source_lag=request.json['source_lag']
    source_lag_direction=[]
    for k in source_lag:
        si = (int(k.split(":")[0]))
        sid = (int(k.split(":")[1]))
        source_lag_direction.append([si,sid])
    source_lag_direction=rxtx_to_bytes(rxtx_from_list(source_lag_direction,size=256))
    source_lag=lag_to_bytes(lag_from_list([int(k.split(":")[0]) for k in source_lag]))
    print (source_lag)
    print (source_lag_direction)

    source_vlan=request.json['source_vlan']
    source_vlan_direction=[]
    for k in source_vlan:
        si = (int(k.split(":")[0]))
        sid = (int(k.split(":")[1]))
        source_vlan_direction.append([si,sid])
    source_vlan_direction=rxtx_to_bytes(rxtx_from_list(source_vlan_direction,size=4096))
    source_vlan=vlans_to_bytes(vlans_from_list([int(k.split(":")[0]) for k in source_vlan]))
    print (source_vlan)
    print (source_vlan_direction)

    destination=request.json['destination']
    destination=mirror_to_bytes(mirror_from_list(["{}/1/{}".format(k.split(":")[0],k.split(":")[1]) for k in destination]))
    print (destination)

    cpu=request.json['cpu']
    destination_tunnel_ip=request.json['destination_tunnel_ip']
    destination_tunnel_source=request.json['destination_tunnel_source']
    destination_tunnel_dscp=request.json['destination_tunnel_dscp']
    destination_tunnel_vrf=request.json['destination_tunnel_vrf']

    record = switch_mirror_session(switch_name, session, comment, enable, source_interface, source_interface_direction, source_lag, source_lag_direction, source_vlan, source_vlan_direction, destination, cpu, destination_tunnel_ip, destination_tunnel_source, destination_tunnel_dscp, destination_tunnel_vrf)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_mirror_session_schema.jsonify(record)

@app.route("/rest/v1/config/switchMirrorSession/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_switch_mirror_session(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_mirror_session.query.get(id)
        if 'switch_name' in update:
            record.switch_name=request.json['switch_name']
        if 'session' in update:
            record.session=request.json['session']
        if 'comment' in update:
            record.comment=request.json['comment']
        if 'enable' in update:
            record.enable=request.json['enable']
        if 'source_interface' in update:
            source_interface=request.json['source_interface']
            source_interface_direction=[]
            for k in source_interface:
                si = (int(k.split(":")[0])-1)*64+int(k.split(":")[1])
                sid = int(k.split(":")[2])
                source_interface_direction.append([si,sid])
            record.source_interface_direction=rxtx_to_bytes(rxtx_from_list(source_interface_direction,size=640))
            record.source_interface=mirror_to_bytes(mirror_from_list(["{}/1/{}".format(k.split(":")[0],k.split(":")[1]) for k in source_interface]))

        if 'source_lag' in update:
            source_lag=request.json['source_lag']
            source_lag_direction=[]
            for k in source_lag:
                si = (int(k.split(":")[0]))
                sid = (int(k.split(":")[1]))
                source_lag_direction.append([si,sid])
            record.source_lag_direction=rxtx_to_bytes(rxtx_from_list(source_lag_direction,size=256))
            record.source_lag=lag_to_bytes(lag_from_list([int(k.split(":")[0]) for k in source_lag]))

        if 'source_vlan' in update:
            source_vlan=request.json['source_vlan']
            source_vlan_direction=[]
            for k in source_vlan:
                si = (int(k.split(":")[0]))
                sid = (int(k.split(":")[1]))
                source_vlan_direction.append([si,sid])
            record.source_vlan_direction=rxtx_to_bytes(rxtx_from_list(source_vlan_direction,size=4096))
            record.source_vlan=vlans_to_bytes(vlans_from_list([int(k.split(":")[0]) for k in source_vlan]))

        if 'destination' in update:
            destination=request.json['destination']
            record.destination=["{}/1/{}".format(k.split(":")[0],k.split(":")[1]) for k in destination]

        if 'cpu' in update:
            record.cpu=request.json['cpu']
        if 'destination_tunnel_ip' in update:
            record.destination_tunnel_ip=request.json['destination_tunnel_ip']
        if 'destination_tunnel_source' in update:
            record.destination_tunnel_source=request.json['destination_tunnel_source']
        if 'destination_tunnel_dscp' in update:
            record.destination_tunnel_dscp=request.json['destination_tunnel_dscp']
        if 'destination_tunnel_vrf' in update:
            record.destination_tunnel_vrf=request.json['destination_tunnel_vrf']

        sdb.session.commit()
        return switch_mirror_session_schema.jsonify(record)

    if request.method=="DELETE":
        record = switch_mirror_session.query.get(id)
        sdb.session.delete(record)
        try:
            sdb.session.commit()
            return jsonify({"Result": "Success"})
        except:
            return jsonify({"Result": "Failure"})
################################################################# END SWITCH MIRROR SESSION #####

############################################################ API for SWITCH BGP #####
@app.route("/rest/v1/config/switch/bgp", methods=['GET'])
@app.route("/rest/v1/config/switch/bgp/<switch>", methods=['GET'])
@login_required
def get_switch_bgp(switch=""):
    if switch == "":
        all = switch_bgp.query.all()
    else:
        all = switch_bgp.query.filter_by(switch_name=switch).all()
    results = switches_bgp_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/switch/bgp", methods=['POST'])
@login_required
def add_switch_bgp():
    switch_name=request.json['switch_name']
    enable=request.json['enable']
    bgp_timer_keepalive=request.json['bgp_timer_keepalive']
    bgp_timer_hold=request.json['bgp_timer_hold']
    maximum_paths=request.json['maximum_paths']
    redist_connected=request.json['redist_connected']
    redist_connected_rm=request.json['redist_connected_rm']
    redist_static=request.json['redist_static']
    redist_static_rm=request.json['redist_static_rm']
    record = switch_bgp(switch_name, enable, bgp_timer_keepalive,
            bgp_timer_hold, maximum_paths, redist_connected,
            redist_connected_rm, redist_static, redist_static_rm )
    sdb.session.add(record)
    sdb.session.commit()
    return switch_bgp_schema.jsonify(record)

@app.route("/rest/v1/config/switch/bgp/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_switch_bgp(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_bgp.query.get(id)
        if 'id' in update:
            record.id=request.json['id']
        if 'switch_name' in update:
            record.switch_name=request.json['switch_name']
        if 'enable' in update:
            record.enable=request.json['enable']
        if 'bgp_timer_keepalive' in update:
            record.bgp_timer_keepalive=request.json['bgp_timer_keepalive']
        if 'bgp_timer_hold' in update:
            record.bgp_timer_hold=request.json['bgp_timer_hold']
        if 'maximum_paths' in update:
            record.maximum_paths=request.json['maximum_paths']
        if "redist_connected" in update:
            record.redist_connected=request.json['redist_connected']
        if "redist_connected_rm" in update:
            record.redist_connected_rm=request.json['redist_connected_rm']
        if "redist_static" in update:
            record.redist_static=request.json['redist_static']
        if "redist_static_rm" in update:
            record.redist_static_rm=request.json['redist_static_rm']
        sdb.session.commit()
        return switch_bgp_schema.jsonify(record)

    if request.method=="DELETE":
        record = switch_bgp.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_bgp_schema.jsonify(record)
################################################################# END BGP #####

############################################################ API for BGP NEIGHBOR #####
@app.route("/rest/v1/config/switch/neighbor/bgp", methods=['GET'])
@app.route("/rest/v1/config/switch/neighbor/bgp/bySwitch/<switch>", methods=['GET'])
@app.route("/rest/v1/config/switch/neighbor/bgp/byNeighbor/<neighbor>", methods=['GET'])
@app.route("/rest/v1/config/switch/neighbor/bgp/byAS/<asNum>", methods=['GET'])
@app.route("/rest/v1/config/switch/neighbor/bgp/byID/<id>", methods=['GET'])
@login_required
def get_bgp_neighbor(switch="", neighbor="", asNum="", id=""):
    if switch != "":
        all = switch_bgp_neighbor.query.filter_by(switch_name = switch).all()
    elif neighbor != "":
        all = switch_bgp_neighbor.query.filter_by(neighbor_ip = neighbor).all()
    elif asNum != "":
        all = switch_bgp_neighbor.query.filter_by(remote_as = asNum).all()
    elif id != "":
        all = switch_bgp_neighbor.query.filter_by(id = id).all()
    else: 
        all = switch_bgp_neighbor.query.all()
    results = switch_bgp_neighbors_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/switch/neighbor/bgp", methods=['POST'])
@login_required
def add_bgp_neighbor():
    switch_name=request.json['switch_name']
    neighbor_ip=request.json['neighbor_ip']
    remote_as=request.json['remote_as']
    local_as=request.json['local_as']
    vrf=request.json['vrf']
    description=request.json['description']
    enabled=request.json['enabled']
    password=request.json['password']
    local_as_prepend=request.json['local_as_prepend']
    local_as_replace=request.json['local_as_replace']
    remove_private_as=request.json['remove_private_as']
    fast_external_failover=request.json['fast_external_failover']
    fallover_bfd=request.json['fallover_bfd']
    update_source=request.json['update_source']
    update_source_type=request.json['update_source_type']
    bgp_timer_neighbor=request.json['bgp_timer_neighbor']
    bgp_timer_keepalive=request.json['bgp_timer_keepalive']
    bgp_timer_hold=request.json['bgp_timer_hold']
    bgp_passive=request.json['bgp_passive']
    address_family=request.json['address_family']
    rm_inbound=request.json['rm_inbound']
    rm_outbound=request.json['rm_outbound']
    record = switch_bgp_neighbor(switch_name, neighbor_ip, remote_as, local_as, vrf, description, enabled, password, local_as_prepend, local_as_replace, remove_private_as, fast_external_failover, fallover_bfd, update_source, update_source_type, bgp_timer_neighbor, bgp_timer_keepalive, bgp_timer_hold, bgp_passive, address_family, rm_inbound, rm_outbound)
    result = record.to_dict()
    result["id"] = None
    sdb.session.add(record)
    sdb.session.commit()
    syslog.info("{} --> ADDED BGP NEIGHBOR IN CONTROL CONFIG ({}, {}, {})".format(session["name"], switch_name, neighbor_ip, result))
    return result

@app.route("/rest/v1/config/switch/neighbor/bgp/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_bgp_neighbor(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_bgp_neighbor.query.get(id)
        if "switch_name" in update:
            record.switch_name=request.json['switch_name']
        if "neighbor_ip" in update:
            record.neighbor_ip=request.json['neighbor_ip']
        if "remote_as" in update:
            record.remote_as=request.json['remote_as']
        if "local_as" in update:
            record.local_as=request.json['local_as']
        if "vrf" in update:
            record.vrf=request.json['vrf']
        if "description" in update:
            record.description=request.json['description']
        if "enabled" in update:
            record.enabled=request.json['enabled']
        if "password" in update:
            record.password=request.json['password']
        if "local_as_prepend" in update:
            record.local_as_prepend=request.json['local_as_prepend']
        if "local_as_replace" in update:
            record.local_as_replace=request.json['local_as_replace']
        if "remove_private_as" in update:
            record.remove_private_as=request.json['remove_private_as']
        if "fast_external_failover" in update:
            record.fast_external_failover=request.json['fast_external_failover']
        if "fallover_bfd" in update:
            record.fallover_bfd=request.json['fallover_bfd']
        if "update_source" in update:
            record.update_source=request.json['update_source']
        if "update_source_type" in update:
            record.update_source_type=request.json['update_source_type']
        if "bgp_timer_neighbor" in update:
            record.bgp_timer_neighbor=request.json['bgp_timer_neighbor']
        if "bgp_timer_keepalive" in update:
            record.bgp_timer_keepalive=request.json['bgp_timer_keepalive']
        if "bgp_timer_hold" in update:
            record.bgp_timer_hold=request.json['bgp_timer_hold']
        if "bgp_passive" in update:
            record.bgp_passive=request.json['bgp_passive']
        if "address_family" in update:
            record.address_family=request.json['address_family']
        if "rm_inbound" in update:
            record.rm_inbound=request.json['rm_inbound']
        if "rm_outbound" in update:
            record.rm_outbound=request.json['rm_outbound']
        sdb.session.commit()
        syslog.info("{} --> MODIFIED BGP NEIGHBOR IN CONTROL CONFIG ({}, {})".format(session["name"], record.switch_name, record.neighbor_ip))
        return switch_bgp_neighbor_schema.jsonify(record)

    if request.method=="DELETE":
        record = switch_bgp_neighbor.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        syslog.info("{} --> DELETED BGP NEIGHBOR IN CONTROL CONFIG ({}, {})".format(session["name"], record.switch_name, record.neighbor_ip))
        return switch_bgp_neighbor_schema.jsonify(record)
################################################################# END BGP NEIGHBOR #####

###################################################### API for SWITCH GLOBAL HELPER #####
@app.route("/rest/v1/config/global/helpers", methods=['GET'])
@login_required
def get_global_helper():
    all = switch_global_helpers.query.all()
    results = switch_global_helpers_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/global/helpers", methods=['POST'])
@login_required
def add_global_helper():
    ip_addr = request.json['ip_addr']
    record = switch_global_helpers(ip_addr)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_global_helper_schema.jsonify(record)

@app.route("/rest/v1/config/global/helpers/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_global_helper(id):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_global_helpers.query.get(id)
        if "ip_addr" in update:
            record.ip_addr = request.json['ip_addr']
        sdb.session.commit()
        return switch_global_helper_schema.jsonify(record)

    if request.method=="DELETE":
        record = switch_global_helpers.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_global_helper_schema.jsonify(record)
####################################################### END SWITCH GLOBAL HELPER  #####

################################################ API FOR SECONDARY ADDRESSES  #####
@app.route("/rest/v1/config/switch/<switch>/address/ipv4", methods=['GET'])
@app.route("/rest/v1/config/switch/<switch>/address/ipv4/vlan/<vlan>", methods=['GET'])
@app.route("/rest/v1/config/switch/<switch>/address/ipv4/vlan/<vlan>/addrtype/<addrtype>", methods=['GET'])
@login_required
def get_switch_ipv4_address(switch="", vlan="", addrtype=""):
    if switch != "" and vlan == "" and addrtype == "":
        all = switch_ipv4_addresses.query.filter_by(switch_name=switch).all()
    if switch != "" and vlan != "" and addrtype == "":
        all = switch_ipv4_addresses.query.filter_by(switch_name=switch,vlan=vlan).all()
    elif switch != "" and vlan != "" and addrtype != "":
        all = switch_ipv4_addresses.query.filter_by(switch_name=switch,vlan=vlan,addr_type=addrtype).all()
    else:
        all = switch_ipv4_addresses.query.all()
    results = switch_ipv4_addresses_schema.dump(all)
    return jsonify(results)

@app.route("/rest/v1/config/switch/<switch>/address/ipv4", methods=['POST'])
@login_required
def add_switch_ipv4_address(switch=""):
    switch_name=request.json['switch_name']
    vlan=request.json['vlan']
    ip_addr=request.json['ip_addr']
    addr_type=request.json['addr_type']
    ip_addr_extra=request.json['ip_addr_extra']
    record = switch_ipv4_addresses(switch_name, vlan, ip_addr, addr_type,
            ip_addr_extra)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_ipv4_address_schema.jsonify(record)

@app.route("/rest/v1/config/switch/<switch>/address/ipv4/vlan/<vlan>/addrtype/<addrtype>", methods=["DELETE"])
@app.route("/rest/v1/config/switch/<switch>/address/ipv4/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_switch_ipv4_address(switch="",id="",vlan="",addrtype=""):
    if request.method=="PUT":
        update = request.json.keys()
        record = switch_ipv4_addresses.query.get(id)
        if "switch_name" in update:
            record.switch_name=request.json['switch_name']
        if "vlan" in update:
            record.vlan=request.json['vlan']
        if "ip_addr" in update:
            record.ip_addr=request.json['ip_addr']
        if "addr_type" in update:
            record.addr_type=request.json['addr_type']
        if "ip_addr_extra" in update:
            record.ip_addr_extra=request.json['ip_addr_extra']
        sdb.session.commit()
        return switch_ipv4_address_schema.jsonify(record)

    if request.method=="DELETE":
        record=None
        if id == "" and switch != "" and vlan != "" and addrtype != "":
            records = switch_ipv4_addresses.query.filter_by(switch_name=switch,
                    vlan=vlan,addr_type=addrtype).all()
            for record in records:
                sdb.session.delete(record)
                sdb.session.commit()
        else:
            record = switch_ipv4_addresses.query.get(id)
            sdb.session.delete(record)
            sdb.session.commit()
        return switch_ipv4_address_schema.jsonify(record)
################################################################# END STUB #####

################################################### API for switch_models #####
@app.route("/rest/v1/config/switchModels", methods=['GET'])
@login_required
def get_switch_models():
    all = switch_models.query.all()
    results = switch_models_schema.dump(all)
    return jsonify(results)

################################################ API for reorder switch #####
@app.route("/rest/v1/config/switchReorder/<id>", methods=["PUT"])
@login_required
def reorder_switch(id):
    success=False
    if request.method=="PUT" and id is not None:
        update = request.json.keys()
        remap = {}
        if "newOrder" in update:
            print ("newOrder",request.json["newOrder"])
            try:
                success=True
                #pass 1 - renumber records to avoid unique key constraint
                for i, switch in enumerate(request.json["newOrder"]):
                    record = site_switches.query.get(switch["did"])
                    if record.switch_number == switch["oid"] and record.switch_name == id.decode():
                        record.switch_number = 99-i
                        remap[switch["oid"]] = record.switch_number
                    else:
                        success=False
                #pass 2 - put to new order
                for switch in request.json["newOrder"]:
                    record = site_switches.query.get(switch["did"])
                    if remap[switch["oid"]] == record.switch_number and record.switch_name == id.decode():
                        record.switch_number = switch["sid"]
                    else:
                        success=False
            except Exception as e:
                print (e)
                success=False
    if success:
        # only commit if all operations were successful
        sdb.session.commit()
        return ({"status": "success"})
    else:
        sdb.session.rollback()
        return ({"status" : "error"})

###################################################### END REORDER SWITCH #####

############################################################ API for RENAME ###
@app.route("/rest/v1/config/switchRename/<id>/<name>", methods=["PUT"])
def modify_switch_name(id, name):
    stack = {}
    name=name.upper()
    fail=False
    if request.method=="PUT":
        try:
            original_record = site_switches.query.get(id)
            original_name = original_record.switch_name
            requested_name = site_switches.query.filter_by(switch_name=name).first()
            if requested_name is None:
                if len(original_name)>0:
                    for item in name_key_tables.keys():
                        tempList = []
                        if "dbentity" in name_key_tables[item].keys():
                            dbentity = name_key_tables[item]["dbentity"]
                            record = dbentity.query.filter_by(switch_name=original_name).all()
                            if record is not None:
                                if type(record) is list:
                                    for row in record:
                                        row.switch_name = name
                                else:
                                    record.switch_name = name
                    sdb.session.commit()
                    return jsonify({'Result': 'Success', 'Action': 'Switch Rename', 'Old_Switch_Name': original_name, 'New_Switch_Name': name})
                else:
                    sdb.session.rollback()
                    return jsonify({'Result': 'Failure', 'Action': 'Switch Rename', 'Old_Switch_Name': original_name, 'New_Switch_Name': name,
                                    'Error_Message': 'The new switch name is not valid'}), 406
            else:
                sdb.session.rollback()
                return jsonify({'Result': 'Failure', 'Action': 'Switch Rename', 'Old_Switch_Name': original_name, 'New_Switch_Name': name,
                                'Error_Message': 'The new switch name already exists.'}), 409
        except Exception as e:
            sdb.session.rollback()
            return jsonify({'Result': 'Failure', 'Action': 'Switch Rename', 'Error_Message': repr(e)}), 400

############################################################ END API for RENAME #####

############################################################ API for REZONE ###
@app.route("/rest/v1/config/switchRezone/<name>/<zone>", methods=["PUT"])
def modify_switch_zone(name, zone):
    name=name.upper()
    if request.method=="PUT" and int(zone) in [1,2,3,4,5,6]:
        original_records = site_switches.query.filter_by(switch_name=name).all()
        for record in original_records:
            record.type = int(zone)
    elif request.method=="PUT":
        sdb.session.rollback()
        return jsonify({'Result': 'Failure', 'Action': 'Switch Zone Change', 'Error_Message': 'Target zone is invalid.'}), 404
    sdb.session.commit()
    #return jsonify(site_switches_schema.dump(original_records))
    return jsonify({'Result': 'Success', 'Action': 'Switch Zone Change'})

############################################################ END API for REZONE #####

############################################################ API for REMODEL ###
@app.route("/rest/v1/config/switchRemodel/<id>/<model>", methods=["PUT"])
def modify_switch_model(id, model):
    if request.method=="PUT":
        all = switch_models.query.all()
        if sys.version_info[0] > 2:
            validModels = [row["model"] for row in switch_models_schema.dump(all)]
        else:
            validModels = [row["model"] for row in switch_models_schema.dump(all)[0]]
        model=model.upper()
        if model in validModels:
            record = site_switches.query.get(id)
            try:
                record.model = model
                sdb.session.commit()
                return site_switch_schema.jsonify(record)
            except:
                sdb.session.rollback()
                return jsonify("{error: 'Issue with switch ID'}"), 404
        else:
            return jsonify("{error: 'Target model is not in database.'}"), 404
    return jsonify("{error: 'not supported'}")
############################################################ API for REMODEL #####

############################################################ API for STUB #####
@app.route("/rest/v1/config/stub", methods=['GET'])
@login_required
def get_stub():
    pass
#    all = _dbentity_.query.all()
#    results = _schema.dump(all)
#    return jsonify(results)

@app.route("/rest/v1/config/stub", methods=['POST'])
@login_required
def add_stub():
    pass
#   _fields_ = json[_fields_]
#    record = _dbentity_(_fields_)
#    sdb.session.add(record)
#    sdb.session.commit()
#    return _schema.jsonify(record)

@app.route("/rest/v1/config/stub/<id>", methods=["PUT", "DELETE"])
@login_required
def modify_stub(id):
    if request.method=="PUT":
        pass
#        update = request.json.keys()
#        record = _dbentity.query.get(id)
#        _fields_ = json[_fields_]
#        sdb.session.commit()
#        return _schema.jsonify(record)

    if request.method=="DELETE":
        pass
#        record = _dbentity_.query.get(id)
#        sdb.session.delete(record)
#        sdb.session.commit()
#        return _schema.jsonify(record)
################################################################# END STUB #####

@app.route("/rest/v1/config/dnsServer", methods=['GET'])
@login_required
def get_dns_servers():
    all_dns = DNSServer.query.all()
    results = dns_servers_schema.dump(all_dns)
    return jsonify(results)

@app.route('/rest/v1/config/dnsServer', methods=["POST"])
@login_required
def add_dns_server():
    ip_address = request.json['ip_address']
    new_dns_server = DNSServer(ip_address)
    sdb.session.add(new_dns_server)
    sdb.session.commit()
    return dns_server_schema.jsonify(new_dns_server)

@app.route('/rest/v1/config/dnsServer/<id>', methods=["PUT","DELETE"])
@login_required
def modify_dns_server(id):
    if request.method == 'PUT':
        ip_address = request.json['ip_address']
        id = request.json['id']
        dns_server = DNSServer.query.get(id)
        dns_server.ip_addr = ip_address
        sdb.session.commit()
        return dns_server_schema.jsonify(dns_server)
    if request.method == 'DELETE':
        server = DNSServer.query.get(id)
        sdb.session.delete(server)
        sdb.session.commit()
        return dns_server_schema.jsonify(server)

@app.route("/rest/v1/config/ntpServer", methods=['GET'])
@login_required
def get_ntp_servers():
    records = NTPServer.query.all()
    results = ntp_servers_schema.dump(records)
    return jsonify(results)

@app.route('/rest/v1/config/ntpServer', methods=["POST"])
@login_required
def add_ntp_server():
    ip_address = request.json['server_ip']
    record = NTPServer(ip_address)
    sdb.session.add(record)
    sdb.session.commit()
    return ntp_server_schema.jsonify(record)

@app.route('/rest/v1/config/ntpServer/<id>', methods=["PUT","DELETE"])
@login_required
def modify_ntp_server(id):
    if request.method == 'PUT':
        ip_address = request.json['server_ip']
        id = request.json['id']
        record = NTPServer.query.get(id)
        record.ip_address = ip_address
        sdb.session.commit()
        return ntp_server_schema.jsonify(record)
    if request.method == 'DELETE':
        record = NTPServer.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return ntp_server_schema.jsonify(record)

@app.route("/rest/v1/config/switchMultiVar", methods=['GET'])
@login_required
def get_switch_multi_vars():
    records = switch_multi_vars.query.all()
    results = switch_multi_vars_schema.dump(records)
    return jsonify(results)

@app.route('/rest/v1/config/switchMultiVar', methods=["POST"])
@login_required
def add_switch_multi_vars():
    name = request.json['name']
    description = request.json['description']
    value = request.json['value']
    record = switch_multi_vars(name, description, value)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_multi_var_schema.jsonify(record)

@app.route('/rest/v1/config/switchMultiVar/<id>', methods=["PUT","DELETE"])
@login_required
def modify_switch_multi_vars(id):
    if request.method == 'PUT':
        name = request.json['name']
        description = request.json['description']
        value = request.json['value']
        id = request.json['id']
        record = switch_multi_vars.query.get(id)
        record.name = name
        record.description = description
        record.value = value
        sdb.session.commit()
        return switch_multi_var_schema.jsonify(record)
    if request.method == 'DELETE':
        record = switch_multi_vars.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_multi_var_schema.jsonify(record)

@app.route("/rest/v1/config/site/switchMultiVar", methods=['GET'])
@login_required
def get_switch_site_multi_vars():
    records = switch_site_multi_vars.query.all()
    results = switch_site_multi_vars_schema.dump(records)
    return jsonify(results)

@app.route('/rest/v1/config/site/switchMultiVar/<site>', methods=["POST"])
@login_required
def add_switch_site_multi_vars(site):
    name = request.json['name']
    description = request.json['description']
    value = request.json['value']
    record = switch_site_multi_vars(site, name, description, value)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_site_multi_var_schema.jsonify(record)

@app.route('/rest/v1/config/site/switchMultiVar/<site>/<id>', methods=["PUT","DELETE"])
@login_required
def modify_switch_site_multi_vars(site, id):
    if request.method == 'PUT':
        name = request.json['name']
        description = request.json['description']
        value = request.json['value']
        id = request.json['id']
        record = switch_site_multi_vars.query.get(id)
        record.site = site
        record.name = name
        record.description = description
        record.value = value
        sdb.session.commit()
        return switch_site_multi_var_schema.jsonify(record)
    if request.method == 'DELETE':
        record = switch_site_multi_vars.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_site_multi_var_schema.jsonify(record)

@app.route("/rest/v1/config/globalVlan", methods=['GET'])
@login_required
def get_global_vlans():
    records = global_vlans.query.all()
    results = global_vlans_schema.dump(records)
    return jsonify(results)

@app.route('/rest/v1/config/globalVlan', methods=["POST"])
@login_required
def add_global_vlans():
    name = request.json['name']
    vlan = request.json['vlan']
    record = global_vlans(vlan, name)
    sdb.session.add(record)
    sdb.session.commit()
    return global_vlan_schema.jsonify(record)

@app.route('/rest/v1/config/globalVlan/<id>', methods=["PUT","DELETE"])
@login_required
def modify_global_vlans(id):
    if request.method == 'PUT':
        name = request.json['name']
        vlan = request.json['vlan']
        id = request.json['id']
        record = global_vlans.query.get(id)
        record.vlan = vlan
        record.name = name
        sdb.session.commit()
        return global_vlan_schema.jsonify(record)
    if request.method == 'DELETE':
        record = global_vlans.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return global_vlan_schema.jsonify(record)

@app.route("/rest/v1/config/siteSwitchesVlans", methods=['GET'])
@app.route("/rest/v1/config/siteSwitchesVlans/<site>/<zone>/<switch>", methods=['GET'])
@login_required
def get_switch_vlans(site="",zone=1,switch=""):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    if (switch != "" and site !=""):
        query = s.query("select sdv.*,sv.type,sv.name from switch_device_vlans sdv, site_vlans sv where sv.site='{}' and (sv.type={} or sv.type=1) and sdv.site=sv.site and sdv.vlan=sv.vlan and sdv.switch_name='{}';".format(site, zone, switch))
    else:
        query = s.query("select sdv.*,sv.type,sv.name from switch_device_vlans sdv, site_vlans sv where sdv.vlan=sv.vlan and sdv.site=sv.site;")
    vlans = s.getAllRows(query)
    #eliminate duplicate vlans so only the type we asked for exists
    vl_counts = Counter(v['vlan'] for v in vlans)
    for k in vl_counts:
        #if I have more than 1 VLAN with the same number
        if vl_counts[k]>1:
            #keep the vlan where the zone type is not 1
            vlans = list(filter(lambda i: (i['vlan'] == k and i['type'] != 1) or (i['vlan'] !=k), vlans))
    return jsonify(vlans,{})

@app.route("/rest/v1/config/siteSwitchesVlans/<id>", methods=['PUT'])
@login_required
def modify_switch_vlans(id):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    vlans_on = request.json['vlans_on']
    vlans_off = request.json['vlans_off']
    site = request.json['site']
    for vlan in vlans_on:
        query = "insert into switch_device_vlans (switch_name, vlan, site) values ('{}','{}', '{}');".format(id, vlan, site)
        s.execute(query)
    query = "delete from switch_device_vlans where switch_name='{}' and vlan in ({});".format(id, ",".join(str(vl) for vl in vlans_off))
    s.execute(query)
    return jsonify({})

@app.route("/rest/v1/config/siteVlan", methods=['GET'])
@login_required
def get_site_vlans():
    records = site_vlans.query.all()
    results = site_vlans_schema.dump(records)
    return jsonify(results)

@app.route('/rest/v1/config/siteVlan', methods=["POST"])
@login_required
def add_site_vlans():
    site = request.json['site']
    name = request.json['name']
    vlan = request.json['vlan']
    zone_type = request.json['zone_type'] or 1
    shutdown = int(request.json['shutdown'] or 0)
    voice = int(request.json['voice'] or 0)
    igmp = request.json['igmp'] or 0
    acl_in_mac = request.json['acl_in_mac'] or ""
    acl_out_mac = request.json['acl_out_mac'] or ""
    acl_in_ip = request.json['acl_in_ip'] or ""
    acl_out_ip = request.json['acl_out_ip'] or ""
    client_tracking = int(request.json['client_tracking'] or 0)
    dhcp_snooping = int(request.json['dhcp_snooping'] or 0)
    #print ("xxxxxx data: ",shutdown, voice, igmp, client_tracking,dhcp_snooping)
    record = site_vlans(site, vlan, name,  zone_type, shutdown, voice, igmp, dhcp_snooping, client_tracking, acl_in_ip, acl_out_ip, acl_in_mac, acl_out_mac)
    sdb.session.add(record)
    sdb.session.commit()
    return site_vlan_schema.jsonify(record)

@app.route('/rest/v1/config/siteVlan/<id>', methods=["PUT","DELETE"])
@login_required
def modify_site_vlans(id):
    if request.method == 'PUT':
        id = request.json["id"]
        site = request.json["site"]
        name = request.json['name']
        vlan = request.json['vlan']
        vlan_type = request.json['zone_type'] or 1
        shutdown = 1 if request.json['shutdown'] in ('True', u'true', True) else 0
        voice = 1 if request.json['voice'] in ('True', u'true', True)  else 0
        igmp = request.json['igmp'] or 0
        acl_in_mac = request.json['acl_in_mac']
        acl_out_mac = request.json['acl_out_mac']
        acl_in_ip = request.json['acl_in_ip']
        acl_out_ip = request.json['acl_out_ip']
        client_tracking = 1 if request.json['client_tracking'] in ('True', u'true', True)  else 0
        dhcp_snooping = 1 if request.json['dhcp_snooping'] in ('True', u'true', True)  else 0
        record = site_vlans.query.get(id)
        record.site = site
        record.vlan = vlan
        record.name = name
        record.type = vlan_type 
        record.shutdown = shutdown
        record.voice = voice
        record.igmp = igmp
        record.client_tracking = client_tracking
        record.dhcp_snooping = dhcp_snooping
        record.acl_in_mac = acl_in_mac
        record.acl_out_mac = acl_out_mac
        record.acl_in_ip = acl_in_ip
        record.acl_out_ip = acl_out_ip
        sdb.session.commit()
        return site_vlan_schema.jsonify(record)
    if request.method == 'DELETE':
        record = site_vlans.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return site_vlan_schema.jsonify(record)

@app.route("/rest/v1/config/siteSwitches", methods=['GET'])
@app.route("/rest/v1/config/filteredsiteSwitches/<site>", methods=['GET'])
@login_required
def get_site_switches(site = ""):
    results = []
    #returns any switch that is switch_number 0 (a chassis switch)
    #or a switch that is switch_number 1 (a stand alone switch or the first switch in a stack)
    query = (
        sdb.session.query(site_switches, switch_models.family)
        .join(switch_models, site_switches.model==switch_models.model)
        .filter(
            ((switch_models.family == '6400') & (site_switches.switch_number == 0)) |
            ((switch_models.family != '6400') & (site_switches.switch_number == 1))
        )        
    )
    #if /rest/v1/config/filteredsiteSwitches/<site> is called add the site filter to the query 
    if site:        
        query = query.filter(site_switches.site == site)        
        
    records = query.all()        
    #Dan's original code - needed to modify because of the chassiss switch
    #The join creates a tuple with the results from the two tables
    #results = [r.serialize() for r in records]
    for site_switch, family in records:
        serialized = site_switch.serialize()  # Use serialize() on the site_switch instance
        serialized["family"] = family  # Add family to the serialized output
        results.append(serialized)
    r = len(records)
    for res in results:
        res["stack_link1"] = str(res["stack_link1"] )
        res["stack_link2"] = str(res["stack_link2"] )

    #I don't know why Dan added the empty dictionary at the end of the results list
    return jsonify([results,{}])

@app.route('/rest/v1/config/siteSwitches', methods=["POST"])
@login_required
def add_site_switch():
    #NOTE - if you modify this API you need to test adding a regular switch as well as stack switches and adding cards to the chassis switch.

    chassis_card_model_list = []
    #returns a list of chassis cards in the switch database, non-chassis cards have a slot_limit of 0
    chassis_card_results = sdb.session.query(switch_models.model).filter(switch_models.slot_limit > 0).all()
    for card in chassis_card_results:
        chassis_card_model_list.append(str(card[0]))
    
    site = request.json['site'].upper() or ""
    model = request.json['model'].upper() or ""
    switch_name = request.json['switch_name'].upper() or ""
    serial = request.json['serial'].upper() or ""
    MAC = request.json['MAC'].upper() or ""
    
    #set switch_number to 0 for the Chassis switch    
    if model == "R0X26C":
        switch_number = 0
    else:
        switch_number = request.json['switch_number'] or 1
    #check that none of the values above are empty or if the switch is a chassis card then skip the serial and MAC check
    if (site != "" and model != "" and switch_name != "" and serial != "" and MAC != "") or (model in chassis_card_model_list and site != "" and model != "" and switch_name != ""):
        #check that the switch name doesn't already exist in the DB
        switch_name_exists = sdb.session.query(site_switches.id).filter_by(switch_name=switch_name).first() is not None
        #changed from >1 to >0
        if not switch_name_exists or int(switch_number) > 0:
            #switch name doesn't yet exist in the DB or the added switch is a stack member
            type = request.json['zone_type'] or 1
            portTypes = "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
            stack_link1 = int(request.json['stack_link1'])
            stack_link2 = int(request.json['stack_link2'])
            record = site_switches(site, model, switch_name, serial, MAC, switch_number, type, portTypes, stack_link1, stack_link2)
            sdb.session.add(record)
            sdb.session.commit()
            return jsonify({'Site': site, 'Switch': switch_name, 'Action': 'Add Switch', 'Result': 'Success'})
        else:
            #switch name already exists in the DB
            return jsonify({'Site': site, 'Switch': switch_name, 'Action': 'Add Switch', 'Result': 'Failure', 'Error_Message': 'Switch name already exists in the DB'})
    else:
        #One or more data values is missing
        return jsonify({'Site': site, 'Switch': switch_name, 'Action': 'Add Switch', 'Result': 'Failure', 'Error_Message': 'Missing required data'})      

@app.route('/rest/v1/config/siteSwitches/<id>', methods=["GET","PUT","DELETE"])
@app.route('/rest/v1/config/siteSwitches/<id>/<number>', methods=["PUT","DELETE"])
@login_required
def modify_site_switches(id,number=""):
    #GET/PUT/DELETE to a specific switch database ID or you can PUT/DELETE to a switch name/number
    #id = switch_name  number = switch_number (its place in the stack)

    #This IF statement takes in an overall switch name(id) and switch number and changes the working id value to the db ID of the specific switch stack member
    if (id != "" and number != "" and int(number) >= 0 and request.method != "GET"):
        temp = site_switches.query.filter_by(switch_name=id, switch_number=number).all()
        print (temp)
        id = temp[0].id #changes the originally inputed switch name as id to the db ID of the stack member
        print ("Changing ID to {}".format(id))
    if request.method == 'GET':
        #records = site_switches.query.join(switch_models,site_switches.model==switch_models.model).order_by(site_switches.switch_number.asc()).filter_by(switch_name=id).all()
        #records = sdb.session.query(site_switches, switch_models).filter(switch_models.model==site_switches.model).filter_by(switch_name=id).all()
        records = site_switches.query.order_by(site_switches.switch_number.asc()).filter_by(switch_name=id).all()
        r = len(records)
        for i in range(0,r):
            records[i].stack_link1 = str(records[i].stack_link1)
            records[i].stack_link2 = str(records[i].stack_link2)
            #records[i].family = records[i].family.family
        results = [r.serialize() for r in records]
        results = [results, {}]
        print ("get siteSwitches/<id>", results)
        return jsonify(results)
    if request.method == 'PUT':
        update = request.json.keys()
        record = site_switches.query.get(id)
        print ("old record", record.serialize())
        if "site" in update: 
            record.site = request.json["site"]
        if "model" in update:
            record.model =  request.json["model"]
        if "switch_name" in update:
            record.switch_name = request.json['switch_name']
        if "switch_number" in update:
            record.switch_number = request.json['switch_number']
        if "zone_type" in update:
            record.type = request.json['zone_type']
        if "serial" in update:
            record.serial = request.json['serial']
        if "MAC" in update:
            record.MAC = request.json['MAC']
        if "portTypes" in update:
            record.portTypes = ",".join(str(e) for e in request.json['portTypes'])
        if "stack_link1" in update:
            record.stack_link1 = int(request.json['stack_link1'])
        if "stack_link2" in update:
            record.stack_link2 = int(request.json['stack_link2'])
        print ("new record", record.serialize())
        #current_app.logger.error("stack_link1 "+request.json['stack_link1'])
        sdb.session.commit()
        results = record.serialize()
        results = [results, {}]
        return jsonify(results)
    if request.method == 'DELETE':
        record = site_switches.query.get(id)
        try:
            sdb.session.delete(record)
            sdb.session.commit()
            return jsonify({'Site': record.site, 'Switch': record.switch_name, 'Action': 'Delete Switch', 'Result': 'Success'})
        except Exception as e:
            return jsonify({'Site': record.site, 'Switch': record.switch_name, 'Action': 'Delete Switch', 'Result': 'Failure', 'Error_Message': str(e)})


@app.route('/rest/v1/config/switchDeviceL3Vlan/', methods=['GET'])
@app.route('/rest/v1/config/switchDeviceL3Vlan/<switch>', methods=["GET"])
@app.route('/rest/v1/config/switchDeviceL3Vlan/<switch>/<vlan>', methods=["GET","PUT","DELETE"])
@login_required
def get_switch_device_l3_vlan(switch="", vlan=""):
    switch = switch.upper()
    if request.method == 'GET':
        if vlan=="" and switch != "":
            records = switch_device_l3vlans.query.order_by(switch_device_l3vlans.vlan.asc()).filter_by(switch_name=switch).all()
        elif switch=="":
            records = switch_device_l3vlans.query.order_by(switch_device_l3vlans.vlan.asc()).all()
        else:
            records = switch_device_l3vlans.query.order_by(switch_device_l3vlans.vlan.asc()).filter_by(switch_name=switch,vlan=vlan).all()
        results = switch_device_l3vlans_schema.dump(records)
        return jsonify(results)
    if request.method == 'PUT':
        switch_name = request.json['switch_name']
        vlan = request.json['vlan']
        record = switch_device_l3vlans.query.filter_by(switch_name=switch_name,vlan=vlan).first()
        record.track = request.json['track']
        record.ip = request.json['ip']
        record.vrrp = request.json['vrrp']
        record.vrf = request.json['vrf']
        record.description = request.json['description']
        record.shutdown = request.json['shutdown']
        record.arp_timeout = request.json['arp_timeout']
        record.ip_mtu = request.json['ip_mtu']
        record.l3_counters = request.json['l3_counters']
        record.ip_directed_broadcast = request.json['ip_directed_broadcast']
        record.ip_neighbor_flood = request.json['ip_neighbor_flood']
        record.ip_dhcp = request.json['ip_dhcp']
        record.ip_proxy_arp = request.json['ip_proxy_arp']
        record.ip_policy_in = request.json['ip_policy_in']
        record.ip_acl_in = request.json['ip_acl_in']
        record.ip_acl_out = request.json['ip_acl_out']
        record.ip_igmp = request.json['ip_igmp']
        record.ip_igmp_querier = request.json['ip_igmp_querier']
        record.ip_enable_helpers = request.json['ip_enable_helpers']
        record.ip_helpers_use_defaults = request.json['ip_helpers_use_defaults']
        sdb.session.commit()
        return switch_device_l3vlan_schema.jsonify(record)
    if request.method == 'DELETE':
        switch_name = switch
        vlan = vlan
        record = switch_device_l3vlans.query.filter_by(switch_name=switch_name,vlan=vlan).first()
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_device_l3vlan_schema.jsonify(record)

@app.route('/rest/v1/config/switchDeviceL3Vlan', methods=["POST"])
@login_required
def add_switch_device_l3_vlan():
    switch_name = request.json['switch_name']
    vlan = request.json['vlan']
    ip = request.json['ip']
    track = request.json['track']
    vrrp = request.json['vrrp']
    vrf = request.json['vrf']
    description = request.json['description']
    shutdown = request.json['shutdown']
    arp_timeout = request.json['arp_timeout']
    ip_mtu = request.json['ip_mtu']
    l3_counters = request.json['l3_counters']
    ip_directed_broadcast = request.json['ip_directed_broadcast']
    ip_neighbor_flood = request.json['ip_neighbor_flood']
    ip_dhcp = request.json['ip_dhcp']
    ip_proxy_arp = request.json['ip_proxy_arp']
    ip_policy_in = request.json['ip_policy_in']
    ip_acl_in = request.json['ip_acl_in']
    ip_acl_out = request.json['ip_acl_out']
    ip_igmp = request.json['ip_igmp']
    ip_igmp_querier = request.json['ip_igmp_querier']
    ip_enable_helpers = request.json['ip_enable_helpers']
    ip_helpers_use_defaults = request.json['ip_helpers_use_defaults']
    record = switch_device_l3vlans(switch_name, vlan, ip, track, vrrp, vrf,
            description, shutdown, arp_timeout, ip_mtu, l3_counters,
            ip_directed_broadcast, ip_neighbor_flood, ip_dhcp, ip_proxy_arp,
            ip_policy_in, ip_acl_in, ip_acl_out, ip_igmp, ip_igmp_querier,
            ip_enable_helpers, ip_helpers_use_defaults)
    sdb.session.add(record)
    sdb.session.commit()
    return switch_device_l3vlan_schema.jsonify(record)

@app.route('/rest/v1/config/switchDeviceL3Vlan/<id>', methods=["PUT","DELETE"])
@login_required
def modify_switch_device_l3_vlan(id):
    if request.method == 'PUT':
        id = request.json["id"]
        switch_name = request.json['switch_name']
        vlan = request.json['vlan']
        track = request.json['track']
        vrrp = request.json['vrrp']
        vrf = request.json['vrf']
        description = request.json['description']
        shutdown = request.json['shutdown']
        arp_timeout = request.json['arp_timeout']
        ip_mtu = request.json['ip_mtu']
        l3_counters = request.json['l3_counters']
        ip_directed_broadcast = request.json['ip_directed_broadcast']
        ip_neighbor_flood = request.json['ip_neighbor_flood']
        ip_dhcp = request.json['ip_dhcp']
        ip_proxy_arp = request.json['ip_proxy_arp']
        ip_policy_in = request.json['ip_policy_in']
        ip_acl_in = request.json['ip_acl_in']
        ip_acl_out = request.json['ip_acl_out']
        ip_igmp = request.json['ip_igmp']
        ip_igmp_querier = request.json['ip_igmp_querier']
        ip_enable_helpers = request.json['ip_enable_helpers']
        record = site_switches.query.get(id)
        record.switch_name = switch_name
        record.vlan = vlan
        record.track = track
        record.vrrp = vrrp
        record.vrf = vrf
        record.description = description
        record.shutdown = shutdown
        record.arp_timeout = arp_timeout
        record.ip_mtu = ip_mtu
        record.l3_counters = l3_counters
        record.ip_directed_broadcast = ip_directed_broadcast
        record.ip_neighbor_flood = ip_neighbor_flood
        record.ip_dhcp = ip_dhcp
        record.ip_proxy_arp = ip_proxy_arp
        record.ip_policy_in = ip_policy_in
        record.ip_acl_in = ip_acl_in
        record.ip_acl_out = ip_acl_out
        record.ip_igmp = ip_igmp
        record.ip_igmp_querier = ip_igmp_querier
        record.ip_enable_helpers = ip_enable_helper
        sdb.session.commit()
        return switch_device_l3vlans_scehma.jsonify(record)
    if request.method == 'DELETE':
        record = switch_device_l3vlans.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return switch_device_l3vlans_schema.jsonify(record)

@app.route("/rest/v1/config/gmiSites", methods=['GET'])
@login_required
def get_gmi_sites():
    records = gmi_sites.query.all()
    results = gmi_sites_schema.dump(records)
    return jsonify(results), 200

@app.route("/rest/v1/config/gmiSites/siteCodeOnly", methods=['GET'])
@login_required
#returns only the list of site codes with a default sort of ascending
def get_gmi_sites_site_code_only():
    sort = request.args.get('sort', "asc", type=str)
    if sort == "desc":
        sort_order = desc(gmi_sites.site)
    else:
        sort_order = asc(gmi_sites.site)
    records = gmi_sites.query.with_entities(gmi_sites.site).order_by(sort_order).all()
    results = gmi_sites_schema.dump(records)
    return jsonify(results), 200

@app.route('/rest/v1/config/gmiSites', methods=["POST"])
@login_required
def add_gmi_sites():
    #Initialize required fields
    site = request.json['site'].upper() or ""
    region = request.json['region'] or ""
    #check that none of the values above are empty
    if (site != "" and region != ""):
        #check that the site name doesn't already exist in the DB
        site_name_exists = sdb.session.query(gmi_sites.site).filter_by(site=request.json['site']).scalar() is not None
        if not site_name_exists:
            address = request.json['address'] or ""
            type = request.json['type'] or ""
            city = request.json['city'] or ""
            state = request.json['state'] or ""
            country = request.json['country'] or ""
            nickname = request.json['nickname'] or ""
            site_override = request.json['site_override'] or ""
            dhcp_override = request.json['dhcp_override'] or ""
            lat = request.json['lat'] or ""
            lng = request.json['lng'] or ""
            postal_code = request.json['postal_code'] or ""
            aruba_central_id = request.json['aruba_central_id'] or ""
            address2 = request.json['address2'] or ""
            address3 = request.json['address3'] or ""
            attention = request.json['attention'] or ""
            active = 1
            suffix = request.json['suffix'] or ""
            record = gmi_sites(site, type, address, city, state, country, nickname, region, 0, site_override, dhcp_override, 
                               lat, lng, postal_code, aruba_central_id, address2, address3, suffix, attention, active)
            sdb.session.add(record)
            sdb.session.commit()
            return jsonify({'Site': request.json['site'], 'Action': 'Add Site', 'Result': 'Success'})
        else:
            return jsonify({'Site': request.json['site'], 'Action': 'Add Site', 'Result': 'Failure', 'Error_Message': 'The site name already exists in the database'})
    else:
        return jsonify({'Site': request.json['site'], 'Action': 'Add Site', 'Result': 'Failure', 'Error_Message': 'Required fields were empty.'})


@app.route('/rest/v1/config/gmiSites/<id>', methods=["PUT","DELETE"])
@login_required
def modify_gmi_sites(id):
    new_site_val = None
    old_site_val = None
    site_changed = False
    proceed_set = False
    if request.method == 'PUT':
        update = request.json.keys()
        record = gmi_sites.query.get(id)
        #print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-UPDATE*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-")
        if "site" in update:
            if record.site != request.json['site']:
                old_site_val = record.site
                if request.json['proceed_confirm_site']=='NO':
                    switches_result = site_switches.query.filter_by(site=record.site).all()
                    temp_list = []
                    for switch in switches_result:
                        temp_list.append(switch.switch_name)
                    if temp_list:
                        return jsonify({"Result":"Failed"})
                else:
                    proceed_set = True
                record.site = request.json['site']
                site_changed = True
                new_site_val = request.json['site'] 
                update_vlan_site_q = "UPDATE site_vlans SET site = '{}' "\
                 "WHERE site = '{}'".format(new_site_val, old_site_val)
                update_vars_site_q = "UPDATE switch_site_multi_vars SET site = '{}' "\
                 "WHERE site = '{}'".format(new_site_val, old_site_val)
                update_switch_site_q = "UPDATE site_switches SET site = '{}' "\
                 "WHERE site = '{}'".format(new_site_val, old_site_val)
        if "type" in update:
            record.type = request.json['type']
        if "address" in update:
            record.address = request.json['address']
        if "city" in update:
            record.city = request.json['city']
        if "state" in update:
            record.state = request.json['state']
        if "country" in update:
            record.country = request.json['country']
        if "nickname" in update:
            record.nickname = request.json['nickname']
        if "region" in update:
            record.region = request.json['region']
        if "site_override" in update:
            record.site_override = request.json['site_override']
        if "dhcp_override" in update:
            record.dhcp_override = request.json['dhcp_override']
        if "lat" in update:
            record.lat = request.json['lat']
        if "lng" in update:
            record.lng = request.json['lng']
        if "postal_code" in update:
            record.postal_code = request.json['postal_code']
        if "aruba_central_id" in update:
            record.aruba_central_id = request.json['aruba_central_id']
        if "address2" in update:
            record.address2 = request.json['address2']
        if "address3" in update:
            record.address3 = request.json['address3']
        if "attention" in update:
            record.attention = request.json['attention']
        if "suffix" in update:
            request.suffix = request.json['suffix']
        if "active" in update:
            # print(request.json['active'])
            record.active = request.json['active']
        sdb.session.commit()
        if site_changed:
            s = sql(dbUser='dan', dbHost=env.DB, dbPassword=dbpw)
            if proceed_set:
                s.query(update_switch_site_q)
            s.query(update_vlan_site_q)
            s.query(update_vars_site_q)
        return jsonify({"Result":"Success"})
    if request.method == 'DELETE':
        record = gmi_sites.query.get(id)
        #print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-UPDATE*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-")
        switches_result = site_switches.query.filter_by(site=record.site).all()
        temp_list = []
        for switch in switches_result:
            temp_list.append(switch.switch_name)
        if temp_list:
            return jsonify({"Result":"Failed"})   
        else:
            sdb.session.delete(record)
            sdb.session.commit()
            return jsonify({"Result":"Success"})

@app.route("/rest/v1/config/coreAS", methods=['GET'])
@app.route("/rest/v1/config/coreAS/<switch>", methods=['GET'])
@login_required
def get_coreas(switch=""):
    if switch == "":
        all_coreAS = sla_locations.query.all()
    else:
        all_coreAS = sla_locations.query.filter_by(core = switch).all()
    results = sla_locations_schema.dump(all_coreAS)
    return jsonify(results)

@app.route('/rest/v1/config/coreAS', methods=["POST"])
@login_required
def add_coreas():
    core = request.json['core']
    description = request.json['description']
    asNum = request.json['asNum']
    new_coreAS = sla_locations(core, description, asNum)
    sdb.session.add(new_coreAS)
    sdb.session.commit()
    return sla_location_schema.jsonify(new_coreAS)

@app.route('/rest/v1/config/coreAS/<id>', methods=["PUT","DELETE"])
@login_required
def modify_coreas(id):
    if request.method == 'PUT':
        update = request.json.keys()
        record = sla_locations.query.get(id)
        if "core" in update:
            record.core = request.json['core']
        if "description" in update:
            record.description = request.json['description']
        if "asNum" in update:
            record.asNum = request.json['asNum']
        sdb.session.commit()
        return sla_location_schema.jsonify(record)
    if request.method == 'DELETE':
        record = sla_locations.query.get(id)
        sdb.session.delete(record)
        sdb.session.commit()
        return sla_location_schema.jsonify(record)

def formatDollar(value):
    dollar = "${:>12,.0f}"
    try:
        return dollar.format(value)
    except:
        return value

def replaceQueryString(field,value,clear="",clear2=""):
    query_string = parse_qs(request.query_string, keep_blank_values=True)
    if clear and clear.encode() in query_string:
        del query_string[clear.encode()]
    if clear2 and clear2.encode() in query_string:
        del query_string[clear2.encode()]
    if field.encode() in query_string:
        del query_string[field.encode()]
    new_query_string = urlencode(query_string,doseq=True)+"&"+field+"="+value
    return new_query_string

def replaceQueryStrings(kv):
    syslog.info(kv)
    query_string = parse_qs(request.query_string, keep_blank_values=False)
    for k, v in kv.items():
        if k.encode() in query_string:
            del query_string[k.encode()]
        query_string[k] = v
    new_query_string = urlencode(query_string,doseq=True)
    return new_query_string

def replaceSortOrder(key=""):
    direction = request.args.get('direction')
    direction = 1 if direction=='0' or direction=='' else 0
    new_query_string = replaceQueryStrings ( { "orderBy":key, "direction":direction } )
    return new_query_string

def getOverrideProducts():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select id,product from samurai_products where capital>0 and current order by product")
    result = s.getAllRows(query)
    return (result)

def getSites():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select id,location from samurai_sites order by location")
    result = s.getAllRows(query)
    return (result)

def getRegions():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select id,name from samurai_regions order by name")
    result = s.getAllRows(query)
    return (result)

def getLocations():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select id,location from samurai_locations order by location")
    result = s.getAllRows(query)
    return (result)

def getStates():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select id,name from samurai_states order by id")
    result = s.getAllRows(query)
    return (result)

def getPlanners():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select id,name from samurai_planners order by id")
    result = s.getAllRows(query)
    r = {}
    for row in result:
        r[row["name"]]=row["id"]
    return r

def sortPlanners(planners):
    t = []
    r = ["ALL", "NONE"]
    for planner in planners.keys():
        if (planner != "ALL") and (planner != "NONE"):
            t.append(planner)
    t.sort()
    return r+t

def getSources():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select id,name as description from samurai_sources order by id")
    result = s.getAllRows(query)
    return (result)

@app.route("/hello/world", methods=['GET'])
def helloWorld():
    return render_template("test.html", auth=get_auth())

@app.route("/config/global/istp", methods=['GET'])
@login_required
def form_interface_spantree():
    return render_template("vue_interface_spantree.html", auth=get_auth())

@app.route("/config/global/illdpp", methods=['GET'])
@login_required
def form_interface_lldp():
    return render_template("vue_interface_lldp.html", auth=get_auth())

@app.route("/config/global/irp", methods=['GET'])
@login_required
def form_interface_role():
    return render_template("vue_port_role_profile.html",auth=get_auth())

@app.route("/config/global/iap", methods=['GET'])
@login_required
def form_interface_acls():
    return render_template("vue_interface_acls.html",auth=get_auth())

@app.route("/config/global/ipsp", methods=['GET'])
@login_required
def form_interface_port_security():
    return render_template("vue_interface_port_security.html",auth=get_auth())

@app.route("/config/global/iqp", methods=['GET'])
@login_required
def form_interface_qos():
    return render_template("vue_interface_qos.html",auth=get_auth())

@app.route("/config/global/iigmpp", methods=['GET'])
@login_required
def form_interface_igmp():
    return render_template("vue_interface_igmp.html",auth=get_auth())

@app.route("/config/global/dns", methods=['GET'])
@login_required
def form_dns_servers():
    return render_template("vue_dnsServer.html",auth=get_auth())

@app.route("/config/global/helpers", methods=['GET'])
@login_required
def form_global_helpers():
    return render_template("vue_global_helpers.html",auth=get_auth())

@app.route("/config/global/cpregion", methods=['GET'])
@login_required
def form_global_cpregion():
    return render_template("vue_global_cpregion.html",auth=get_auth())

@app.route("/config/global/par", methods=['GET'])
@login_required
def form_port_access_roles():
    return render_template("vue_port_access_roles.html",auth=get_auth())

@app.route("/config/global/coreAS", methods=['GET'])
@login_required
def form_coreAS():
    return render_template("vue_coreAS.html", auth=get_auth())

@app.route("/config/global/ntp", methods=['GET'])
@login_required
def form_ntp_servers():
    return render_template("vue_ntpServer.html", auth=get_auth())

@app.route("/config/global/multi", methods=['GET'])
@login_required
def form_multi_variables():
    return render_template("vue_multi.html",auth=get_auth())

@app.route("/config/test/stuff", methods=['GET'])
@login_required
def form_test_stuff():
    return render_template("test.html",auth=get_auth())

@app.route("/config/global/vlan", methods=['GET'])
@login_required
def form_global_vlans():
    return render_template("vue_global_vlans.html",auth=get_auth())

@app.route("/config/global/gmiSites", methods=['GET'])
@login_required
def form_gmi_sites():
    return render_template("vue_gmi_sites.html",auth=get_auth())

@app.route("/config/site/vlan", methods=['GET'])
@login_required
def form_site_vlans():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select site from gmi_sites where active = 1 order by site asc;")
    sites = s.getAllRows(query)
    query = s.query("select vlan, name from global_vlans order by vlan asc;")
    vlans = s.getAllRows(query)
    return render_template("vue_site_vlans.html", auth=get_auth(), sites=sites, vlans=vlans)

@app.route("/config/site/switches", methods=['GET'])
@app.route("/config/site/switches/<site>", methods=['GET'])
@login_required
def form_site_switches(site = ""):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select site from gmi_sites where active = 1 order by site asc;")
    sites = s.getAllRows(query)
    query = s.query("select model,description,family,display from switch_models order by model asc;")
    models = s.getAllRows(query)
    return render_template("vue_site_switches.html", auth=get_auth(), sites=sites, models=models)

@app.route("/config/site/multi", methods=['GET'])
@login_required
def form_site_multi_variables():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select site from gmi_sites where active = 1 order by site asc;")
    sites = s.getAllRows(query)
    return render_template("vue_site_multi.html", auth=get_auth(),sites=sites)

def switch_version_breakdown(version):
    pattern1 = "([a-zA-Z]+)\.(\d+)\.(\d+)\.?(.*)?\.?(.*)()"
    pattern2 = "(.+)\s+(\d+)\.(\d+)\.(\d+)(.*)(.*)"                         #Cisco 1
    pattern3 = "(\d+)\.(\d+?).\(?(\d+)\)?([a-zA-Z]+)?(\d+)?\(?(\d+)?\)?"    #Cisco 2
    result = re.split(pattern1, version)
    if len(result)==1:
        result = re.split(pattern2, version)
    if len(result)==1:
        result = re.split(pattern3, version)
    if len(result)==1:
        result = ["","","","","","","",""]
    junk,train,major,minor,rev1,rev2,rev3,junk2 = result
    return ([train,major,minor,rev1,rev2,rev3])

def switch_buildComplianceList():
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select * from switch_compliance where state=50;")
    compliance = s.getAllRows(query)
    result = {}
    for version in compliance:
        (train,major,minor,rev1,rev2,rev3) = switch_version_breakdown(version["version"])
        result[train] = (train,major,minor,rev1,rev2,rev3)
    return (result)

def isnumeric(v):
    isnum=False
    try:
        x=int(v)
        isnum=True
    except:
        pass
    return (isnum)
    
def switch_isCompliant(version,compliantVersion):
    compliant=False
    version = list(map(lambda x: x if x is not None else '', version))
    compliantVersion = list(map(lambda x: x if x is not None else '', compliantVersion))
    if (version[0] >= compliantVersion[0]):
        if (version[1] > compliantVersion[1]):
            compliant=True
        elif (version[1] == compliantVersion[1]):
            if (version[2] > compliantVersion[2]):
                compliant=True
            elif (version[2] == compliantVersion[2]):
                if (version[3] > compliantVersion[3]):
                    compliant=True
                elif (version[3] == compliantVersion[3]):
                    if (version[4] > compliantVersion[4]):
                        compliant=True
                    elif (version[4] == compliantVersion[4]):
                        if (version[5] >= compliantVersion[5]):
                            compliant=True
                        else:
                            compliant=False
    print ("Checking ",version,compliantVersion,compliant)
    return(compliant)
             
@app.route("/switch/config", methods=['GET'])
@app.route("/switch/config/<task>", methods=['GET','POST'])
@login_required
def form_switch_config(task=""):
    s = sql(dbHost=env.DB,dbPassword=dbpw)
    query = s.query("select model,description,family from switch_models order by model asc;")
    models = s.getAllRows(query)
    site = request.args.get('device')
    query = s.query("select sv.name,sv.vlan,sv.type from site_switches ss, site_vlans sv where ss.switch_name='"+site+"' and ss.switch_number=1 and sv.site=ss.site and (sv.type=ss.type or sv.type=1);")
    vlans = s.getAllRows(query)
    #remove duplicate vlans if overlap between default zone and specific zone keep specific
    vl_counts = Counter(v['vlan'] for v in vlans)
    for k in vl_counts:
        if vl_counts[k]>1:
            vlans = list(filter(lambda i: (i['vlan'] == k and i['type'] != 1) or (i['vlan'] !=k), vlans))
    query = s.query("select vlan from switch_device_vlans where switch_name='{}';".format(site))
    dv = s.getAllRows(query)
    device_vlans = []
    for device in dv:
        device_vlans.append(device["vlan"])
    query = s.query("select vlan,ip_enable_helpers from switch_device_l3vlans where switch_name='{}';".format(site))
    l3_vlans = s.getAllRows(query)
    l3 = [i['vlan'] for i in l3_vlans]
    l3helpers = [0 for i in range(0,4096)]
    for i in l3_vlans:
        l3helpers[i["vlan"]]=i["ip_enable_helpers"]
    return render_template("vue_switch.html", auth=get_auth(), switch_name=site,
            models=models, vlans=vlans, device_vlans=device_vlans, l3=l3,
            l3helpers=l3helpers)

@app.route("/reports/<report>", methods=['GET'])
@app.route("/reports/<report>/<modifier>", methods=['GET'])
@app.route("/reports/<report>/<modifier>/<site>", methods=['GET'])
@app.route("/reports/<report>/<modifier>/<site>/<modifier2>", methods=['GET'])
@login_required
def reports(report="",modifier="",site="", modifier2=""):
    if (report=="outageBusinessImpact"):
        return render_template("reports/grafana.html", auth=get_auth(), url="https://{}:{}/d/eduxccugt5a80d/outage-type-filters-prod?orgId=1".format(grafana_server, grafana_port))

    if (report=="wirelessVersionCompliance"):
        return render_template("reports/wireless_grafana.html", auth=get_auth(), url="https://{}:{}/d/dduxerfcmgqgwf/wireless-compliance-dashboard?orgId=1".format(grafana_server, grafana_port))

    if (report=="switchCompliance" and modifier==""):
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        query_all = """select sm.model,sp.product,sm.version,count(sm.model) as total from samurai_master
 as sm, samurai_products sp, samurai_sites ss1,samurai_sites ss2 where lastSeen >= DATE_SUB(now(), interval 30 day) and sm.model=sp.id and 
(ss2.remap_id=ss1.id or ss2.id=ss1.id) and sm.location=ss2.id and
sp.deviceType=2 group by sm.version, sm.model,sp.product order by sp.product desc,sm.version;"""
        query = s.query(query_all)
        all_switches = s.getAllRows(query)
        complianceSwitches = switch_buildComplianceList()
        switch_compliance_list = []
        switchnc=0
        switchc=0
        last_model=all_switches[0]["model"]
        last_version=all_switches[0]["version"]
        last_product=all_switches[0]["product"]
        switch_record = {
                "product":all_switches[0]["product"],
                "total":switchc,
                "version":all_switches[0]["version"],
                "noncompliant":switchnc
        }
        for switch in all_switches:
            if ((switch["model"] != last_model) or (switch["model"] == last_model and switch["version"] != last_version)):
                switch_record["total"]=switchc
                switch_record["noncompliant"]=switchnc
                switch_compliance_list.append(dict(switch_record))
                last_model = switch["model"]
                last_version = switch["version"]
                switch_record["product"]=switch["product"]
                switch_record["version"]=switch["version"]
                switchnc=0
                switchc=0

            (train,major,minor,rev1,rev2,rev3) = switch_version_breakdown(switch["version"])
            try:
                if train in complianceSwitches:
                    if not switch_isCompliant((train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train)]):
                        switchnc = switchnc + switch["total"]
                        switchc = switchc + switch["total"]
                    else:
                        switchc = switchc + switch["total"]
                else:
                    switchc = switchc + switch["total"]
                    switchnc = switchnc + switch["total"]
            except:
                print ("key error finding ",train," for ",switch_record,(train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train),switch_isCompliant((train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train)])])
                switchnc = switchnc + switch["total"]
                switchc = switchc + switch["total"]
        switch_record["total"]=switchc
        switch_record["noncompliant"]=switchnc
        switch_compliance_list.append(switch_record)
        return render_template("reports/switch_compliance_by_model.html",
                auth=get_auth(), all_switches=switch_compliance_list)

    if (report=="switchCompliance" and site != "" and modifier=="bySite" and modifier2=="asExcel"):
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        query_all = """select sm.name,sm.model,sp.product,
            ss1.location as location,sm.version, 1 as total from
            samurai_master as sm, samurai_products sp, samurai_sites
            ss1,samurai_sites ss2 where lastSeen >= DATE_SUB(now(), interval 30
                day) and sm.model=sp.id and (ss2.remap_id=ss1.id or
                    ss2.id=ss1.id) and sm.location=ss2.id and sp.deviceType=2
                and ss1.location='{}' order by sp.product,sm.version desc,sm.name;""".format(site.upper())
        query = s.query(query_all)
        all_switches = s.getAllRows(query)
        complianceSwitches = switch_buildComplianceList()
        switch_compliance_list = []
        switchnc=0
        switchc=0
        last_model=all_switches[0]["model"]
        last_product=all_switches[0]["product"]
        switch_record = {
                "site":all_switches[0]["location"],
                "name":all_switches[0]["name"],
                "product":all_switches[0]["product"],
                "version":all_switches[0]["version"],
                "is_compliant": "Yes"
        }
        for switch in all_switches:
#            switchnc=0
#            switchc=0

            (train,major,minor,rev1,rev2,rev3) = switch_version_breakdown(switch["version"])
            try:
                if train in complianceSwitches:
                    if not switch_isCompliant((train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train)]):
                        switchnc=1
                    else:
                        switchnc=0
                else:
                    switchnc=0
            except:
                print ("key error finding ",train," for ",switch_record,(train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train),switch_isCompliant((train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train)])])
                switchnc = 0

            switch_record["name"]=switch["name"]
            switch_record["is_compliant"]="No" if switchnc==1 else "Yes"
            switch_record["product"]=switch["product"]
            switch_record["version"]=switch["version"]
            switch_record["site"]=switch["location"]
            switch_compliance_list.append(dict(switch_record))

        buffer = io.BytesIO()
        col_order = ['site', 'name', 'is_compliant', 'product', 'version']
        df = pd.DataFrame.from_records(switch_compliance_list)
        df.to_excel(buffer, index=False, columns=col_order, freeze_panes=(1,0))
        headers = {
                'Content-Disposition': "attachment; filename={}-switch-compliance-report.xlsx".format(site.lower()),
                'Content-type': 'application/vnd.ms-excel'
        }
        return Response(buffer.getvalue(), mimetype='application/vnd.ms-excel',
            headers=headers)

    if (report=="switchCompliance" and modifier=="bySite" and modifier2==""):
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        if site == "":
            query_all = """select sm.model,sp.product,sm.location as locId,
            ss1.location as location,sm.version,count(sm.model) as total from
            samurai_master as sm, samurai_products sp, samurai_sites
            ss1,samurai_sites ss2 where lastSeen >= DATE_SUB(now(), interval 30
                    day) and sm.model=sp.id and (ss2.remap_id=ss1.id or
                            ss2.id=ss1.id) and sm.location=ss2.id and
                            sp.deviceType=2
                    group by sm.version, ss1.location, sm.model,sp.product order
                    by sm.location desc,sm.version;"""
        else:
            query_all = """select sm.model,sp.product,sm.location as locId,
            ss1.location as location,sm.version,count(sm.model) as total from
            samurai_master as sm, samurai_products sp, samurai_sites
            ss1,samurai_sites ss2 where lastSeen >= DATE_SUB(now(), interval 30
                day) and sm.model=sp.id and (ss2.remap_id=ss1.id or
                    ss2.id=ss1.id) and sm.location=ss2.id and sp.deviceType=2
                and ss1.location='{}' group by sm.version, ss1.location,
                sm.model,sp.product order by sm.location
                desc,sm.version;""".format(site)
        query = s.query(query_all)
        all_switches = s.getAllRows(query)
        complianceSwitches = switch_buildComplianceList()
        switch_compliance_list = []
        switchnc=0
        switchc=0
        last_site=all_switches[0]["locId"]
        last_model=all_switches[0]["model"]
        last_product=all_switches[0]["product"]
        switch_record = {
                "product":all_switches[0]["product"],
                "total":switchc,
                "version":all_switches[0]["version"],
                "noncompliant":switchnc,
                "site":all_switches[0]["location"],
                "locId":all_switches[0]["locId"]
        }
        for switch in all_switches:
            if ((switch["model"] != last_model)):
                switch_record["total"]=switchc
                switch_record["noncompliant"]=switchnc
                switch_compliance_list.append(dict(switch_record))
                last_model = switch["model"]
                last_site = switch["locId"]
                switch_record["product"]=switch["product"]
                switch_record["version"]=switch["version"]
                switch_record["site"]=switch["location"]
                switch_record["locId"]=switch["locId"]
                switchnc=0
                switchc=0

            (train,major,minor,rev1,rev2,rev3) = switch_version_breakdown(switch["version"])
            try:
                if train in complianceSwitches:
                    if not switch_isCompliant((train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train)]):
                        switchnc = switchnc + switch["total"]
                        switchc = switchc + switch["total"]
                    else:
                        switchc = switchc + switch["total"]
                else:
                    switchc = switchc + switch["total"]
                    switchnc = switchnc + switch["total"]
            except:
                print ("key error finding ",train," for ",switch_record,(train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train),switch_isCompliant((train,major,minor,rev1,rev2,rev3),complianceSwitches[str(train)])])
                switchnc = switchnc + switch["total"]
                switchc = switchc + switch["total"]
        switch_record["total"]=switchc
        switch_record["noncompliant"]=switchnc
        switch_compliance_list.append(switch_record)
        return render_template("reports/switch_compliance_by_site.html",
                auth=get_auth(), all_switches=switch_compliance_list)
    
    if (report=="duplicateMacs"):
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        query = s.query("select * from (select name, product, mac, count(mac) as num from samurai_master, samurai_products sp where model=sp.id and mac is not null and mac<>\"\" and parentSN=\"\" group by mac) as samurai_master where num>1;")
        all_dupes = s.getAllRows(query)
        return render_template("reports/duplicate_macs.html", auth=get_auth(), all_dupes=all_dupes)

@app.route("/samurai", methods=['GET'])
@app.route('/samurai/<task>', methods=['POST'])
@login_required
def samurai_default(task=""):
    today = datetime.datetime.today().date()
    if (task=="changeYear"):
        query_string = parse_qs(request.query_string, keep_blank_values=True)
        records_str = request.form.getlist('records')[0]
        records_str = "{\"records\":["+records_str+"]}"
        records = json.loads(records_str)
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        for record in records["records"]:
            if record["newYear"] == "N":
                query = "update samurai_master set samuraiYear=Null where name='"+record["id"]+"'"
            else:
                query = "update samurai_master set samuraiYear='"+record["newYear"]+"' where name='"+record["id"]+"'"
            s.query(query)
        return redirect("/samurai?"+urlencode(query_string,doseq=True), code=303)
    elif (task=="changeBudget"):
        query_string = parse_qs(request.query_string, keep_blank_values=True)
        records_str = request.form.getlist('records')[0]
        records_str = "{\"records\":["+records_str+"]}"
        records = json.loads(records_str)
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        for record in records["records"]:
            query = "update samurai_master set budgetSource='"+record["newBudget"]+"' where name='"+record["id"]+"'"
            s.query(query)
        return redirect("/samurai?"+urlencode(query_string,doseq=True), code=303)
    elif (task=="changePlanner"):
        query_string = parse_qs(request.query_string, keep_blank_values=True)
        records_str = request.form.getlist('records')[0]
        records_str = "{\"records\":["+records_str+"]}"
        records = json.loads(records_str)
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        for record in records["records"]:
            if record["newPlanner"] != "2":
                query = "update samurai_master set planner='"+record["newPlanner"]+"' where name='"+record["id"]+"'"
                s.query(query)
        return redirect("/samurai?"+urlencode(query_string,doseq=True), code=303)
    elif (task=="retireAssets"):
        query_string = parse_qs(request.query_string, keep_blank_values=True)
        records_str = request.form.getlist('records')[0]
        records_str = "{\"records\":["+records_str+"]}"
        records = json.loads(records_str)
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        for record in records["records"]:
            query = "update samurai_master set state=1 where name='"+record["id"]+"'"
            s.query(query)
        return redirect("/samurai?"+urlencode(query_string,doseq=True), code=303)
    elif (task=="newReplacement"):
        query_string = parse_qs(request.query_string, keep_blank_values=True)
        records_str = request.form.getlist('records')[0]
        records_str = "{\"records\":["+records_str+"]}"
        records = json.loads(records_str)
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        for record in records["records"]:
            query = "update samurai_master set newModel="
            if record["newReplacement"] != 0 and record["newReplacement"] != "0":
                query += "'"+record["newReplacement"]+"'"
            else:
                query += "null"
            query += " where name='"+record["id"]+"'"
            s.query(query)
        return redirect("/samurai?"+urlencode(query_string,doseq=True), code=303)
    elif (task=="newCapital"):
        query_string = parse_qs(request.query_string, keep_blank_values=True)
        records_str = request.form.getlist('records')[0]
        records_str = "{\"records\":["+records_str+"]}"
        records = json.loads(records_str)
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        for record in records["records"]:
            query = "update samurai_master set newCapital="
            if record["newCapital"] != "":
                query += "'"+record["newCapital"]+"'"
            else:
                query += "null"
            query += " where name='"+record["id"]+"'"
            s.query(query)
        return redirect("/samurai?"+urlencode(query_string,doseq=True), code=303)
    elif (task=="changeSite"):
        query_string = parse_qs(request.query_string, keep_blank_values=True)
        records_str = request.form.getlist('records')[0]
        records_str = "{\"records\":["+records_str+"]}"
        records = json.loads(records_str)
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        for record in records["records"]:
            if record["newSite"] != "":
                query = "update samurai_master set location="
                query += "'"+record["newSite"]+"'"
                query += " where name='"+record["id"]+"'"
                s.query(query)
        return redirect("/samurai?"+urlencode(query_string,doseq=True), code=303)
    else:
        sources = getSources()
        snFilter=""
        snFilter = request.args.get('snFilter')
        version = request.args.get('version')
        capital = request.args.get('capital')
        dbSource = request.args.get('dbSource')
        ipaddress = request.args.get('ipaddress', "")
        macaddress = request.args.get('macaddress', "")
        end_of_sale = request.args.get('end_of_sale', "")
        end_of_support = request.args.get('end_of_support', "")
        planners = getPlanners()        
        #added a new list of just the valid IDs of the current planners.  These are integers.  The argument input is a string.
        planner_id_list = list(planners.values())
        planner_display_order = sortPlanners(planners)
        display_order = ["Location","Region","Planner","Budget_Source","Year","Device_Name","Device_Model","Device_New","Serial_Number","Version","Capital","IP_Address","MAC_Address","End_of_Sale","End_of_Support","Last_Seen","DB_Source"]
        overrideProducts = getOverrideProducts()
        states = getStates()
        exportToExcel = int(request.args.get('exportToExcel')) if request.args.get('exportToExcel') else 0
        olderThan = request.args.get('olderThan')
        state = request.args.get('state')
        if state not in [str(i).zfill(1) for i in range(0,len(states))]:
            state="0"
        replacementState = request.args.get('replacementState')
        site = request.args.get('site')
        region = request.args.get('region')
        sites = getSites()
        regions = getRegions()
        if region==0 or region=="0":
            region = None
        if site==0 or site=="0":
            site = None
        parent = request.args.get('parent')
        direction = request.args.get('direction')
        # If filterPlanner is None or not included in request.args, set it to the default of 2.
        filterPlanner = request.args.get('filterPlanner', "2")
        #Check if the planner argument given is in the list of valid planner IDs.  If not, set it to the default of 2.
        #The filterPlanner argument is a string, so it must be converted to an integer to be checked against the list of valid planner IDs.        
        if int(filterPlanner) not in planner_id_list:        
            filterPlanner = "2"
        start = request.args.get('start')
        stop = request.args.get('stop')
        page = request.args.get('page')
        year = request.args.get('year')
        orderBy = request.args.get('orderBy')
        if orderBy in display_order:
            if direction=="1":
                orderBy += " asc"
            else:
                orderBy += " desc"
        else:
            orderBy = None
        deviceName = request.args.get('deviceName')
        if deviceName is None:
            deviceName=""
        deviceModel = request.args.get('deviceModel')
        if deviceModel is None:
            deviceModel=""
        exact = request.args.get('exact')
        if exact is None:
            exact=False
        else:
            exact=True
        deviceNew = request.args.get('deviceNew')
        if deviceNew is None:
            deviceNew=""
        budgetSource = request.args.get('budgetSource')
        if budgetSource=="":
            budgetSource=None
        notAssigned = request.args.get('notAssigned')
        if start is None:
            start = 0
        else:
            start = int(start)
        if page is None:
            page=100
        else:
            page=int(page)
        if stop is None:
            stop = start + page
        else:
            stop = int(stop)
        if stop<start:
            stop = start + page

        if year=="N" or year=="n":
            year=None
            thisYear=None
            notAssigned=1
        if year=="":
            year=None

        if (not year is None):
            years = list(year.split(","))
            thisYear = int(years[0]) % 5
            notAssigned=None
        else:
            thisYear=None

        if orderBy is None:
            orderBy = "Device_Name asc"
        if not deviceModel is None:
            deviceModels = list(deviceModel.split(","))
        if not deviceNew is None:
            deviceNews = list(deviceNew.split(","))
        if not budgetSource is None:
            budgetSources = list(budgetSource.split(","))
        dollar = "${:>12,.0f}"
        s = sql(dbHost=env.DB,dbPassword=dbpw)
        #query1 = "select case when sp.capital<>sm.newCapital then 1 else 0 end as overrideCapital, case when sm.newModel <> sr.productNew and sm.newModel is not null then 1 else 0 end as overrideModel, sl.location as Location, srg.name as Region, srg.factor as factor, sm.id as ID,sps.name as Planner,ss2.name as Budget_Source,sm.name as Device_Name,ss.name as DB_Source,lastSeen as Last_Seen,sm.samuraiYear as Year,sp.product as Device_Model,IFNULL(sp3.product,sp2.product) as Device_New,sm.serialNumber as Serial_Number,sm.parentSN as parentSN,samuraiCountChildren(sm.serialNumber) as childCount,sm.IP as IP_Address,sm.MAC as MAC_Address,sm.version as Version,CASE when sm.newCapital is not null then sm.newCapital when sp3.capital is not null then sp3.capital*srg.factor else sp2.capital*srg.factor end as Capital"
        query1 = """
                SELECT 
                    CASE 
                        WHEN sp.capital <> sm.newCapital THEN 1 
                        ELSE 0 
                    END AS overrideCapital, 
                    CASE 
                        WHEN sm.newModel <> sr.productNew AND sm.newModel IS NOT NULL THEN 1 
                        ELSE 0 
                    END AS overrideModel, 
                    sl.location AS Location, 
                    srg.name AS Region, 
                    srg.factor AS factor, 
                    sm.id AS ID, 
                    sps.name AS Planner, 
                    ss2.name AS Budget_Source, 
                    sm.name AS Device_Name, 
                    ss.name AS DB_Source, 
                    lastSeen AS Last_Seen, 
                    sm.samuraiYear AS Year, 
                    sp.product AS Device_Model,
                    sp.end_of_sale AS End_of_Sale,
                    sp.end_of_support AS End_of_Support, 
                    IFNULL(sp3.product, sp2.product) AS Device_New, 
                    sm.serialNumber AS Serial_Number, 
                    sm.parentSN AS parentSN, 
                    samuraiCountChildren(sm.serialNumber) AS childCount, 
                    sm.IP AS IP_Address, 
                    sm.MAC AS MAC_Address, 
                    sm.version AS Version, 
                    CASE 
                        WHEN sm.newCapital IS NOT NULL THEN sm.newCapital 
                        WHEN sp3.capital IS NOT NULL THEN sp3.capital * srg.factor 
                        ELSE sp2.capital * srg.factor 
                    END AS Capital
                """

        #q1 = " from samurai_master sm join samurai_planners sps on sps.id=sm.planner join samurai_sites sl on sm.location=sl.id join samurai_regions srg on sl.region = srg.id join samurai_replacements sr on sr.productOld=sm.model join samurai_products sp2 on sp2.id=sr.productNew join samurai_sources ss on ss.id=sm.source join samurai_sources ss2 on ss2.id=sm.budgetSource join samurai_products sp on sp.id=sm.model left join samurai_products sp3 on sp3.id=sm.newModel"
        q1 = """
            FROM samurai_master sm
            JOIN samurai_planners sps ON sps.id = sm.planner
            JOIN samurai_sites sl ON sm.location = sl.id
            JOIN samurai_regions srg ON sl.region = srg.id
            JOIN samurai_replacements sr ON sr.productOld = sm.model
            JOIN samurai_products sp2 ON sp2.id = sr.productNew
            JOIN samurai_sources ss ON ss.id = sm.source
            JOIN samurai_sources ss2 ON ss2.id = sm.budgetSource
            JOIN samurai_products sp ON sp.id = sm.model
            LEFT JOIN samurai_products sp3 ON sp3.id = sm.newModel
            """


        q1 += " where 1=1"
        if dbSource != "" and not dbSource is None:
            q1 += " and ss.id = '"+str(dbSource)+"'"
        if ipaddress != "" and not ipaddress is None:
            q1 += " and sm.IP like '%"+ipaddress+"%'"
        if macaddress != "" and not macaddress is None:
            q1 += " and sm.MAC like '%"+macaddress+"%'"
        if end_of_sale != "" and not end_of_sale is None:
            q1 += " and sp.end_of_sale like '%"+end_of_sale+"%'"
        if end_of_support != "" and not end_of_support is None:
            q1 += " and sp.end_of_support like '%"+end_of_support+"%'"
        if capital == "0":
            #q1 += " and (CASE when sm.newCapital is not null then sm.newCapital when sp3.capital is not null then sp3.capital*srg.factor else sp2.capital*srg.factor end)=0"
            q1 += """
                    AND (
                        CASE 
                            WHEN sm.newCapital IS NOT NULL THEN sm.newCapital 
                            WHEN sp3.capital IS NOT NULL THEN sp3.capital * srg.factor 
                            ELSE sp2.capital * srg.factor 
                        END
                    ) = 0
                  """

        if capital == "N":
            #q1 += " and (CASE when sm.newCapital is not null then sm.newCapital when sp3.capital is not null then sp3.capital*srg.factor else sp2.capital*srg.factor end) is NULL"
            q1 += """
                    AND (
                        CASE 
                            WHEN sm.newCapital IS NOT NULL THEN sm.newCapital
                            WHEN sp3.capital IS NOT NULL THEN sp3.capital * srg.factor
                            ELSE sp2.capital * srg.factor
                        END
                    ) IS NULL
                  """
        if capital == "B":
            #q1 += " and ( ((CASE when sm.newCapital is not null then sm.newCapital when sp3.capital is not null then sp3.capital*srg.factor else sp2.capital*srg.factor end)=0) or ((CASE when sm.newCapital is not null then sm.newCapital when sp3.capital is not null then sp3.capital*srg.factor else sp2.capital*srg.factor end) is NULL) )"
            q1 += """
                    AND (
                        (
                            (
                                CASE 
                                    WHEN sm.newCapital IS NOT NULL THEN sm.newCapital
                                    WHEN sp3.capital IS NOT NULL THEN sp3.capital * srg.factor
                                    ELSE sp2.capital * srg.factor
                                END
                            ) = 0
                        ) 
                        OR 
                        (
                            (
                                CASE 
                                    WHEN sm.newCapital IS NOT NULL THEN sm.newCapital
                                    WHEN sp3.capital IS NOT NULL THEN sp3.capital * srg.factor
                                    ELSE sp2.capital * srg.factor
                                END
                            ) IS NULL
                        )
                    )
                  """

        if capital == "S":
            #q1 +=" and (CASE when sm.newCapital is not null then sm.newCapital when sp3.capital is not null then sp3.capital*srg.factor else sp2.capital*srg.factor end)>0"
            q1 += """
                    AND (
                        CASE 
                            WHEN sm.newCapital IS NOT NULL THEN sm.newCapital
                            WHEN sp3.capital IS NOT NULL THEN sp3.capital * srg.factor
                            ELSE sp2.capital * srg.factor
                        END
                    ) > 0
                  """

        if state == "0":
            #q1 += " and not CASE when sm.state is null then sl.state else sm.state end"
            q1 += """
                    AND NOT (
                        CASE 
                            WHEN sm.state IS NULL THEN sl.state 
                            ELSE sm.state 
                        END
                    )
                  """

        else:
#        if state == "1":
            q1 += " and case when sm.state is null then sl.state else sm.state end="+state
#        if state == "2":
#            q1 += " and case when sm.state is null then sl.state else sm.state end=2"
        if parent == "1":
            q1 += " and parentSN=''"

        if snFilter != "" and snFilter is not None:
            q1 += " and sm.serialNumber like '%"+snFilter+"%'"

        if not notAssigned:
            if not year is None:
                q1 = q1 + " and ("
                for y in years:
                    q1 = q1 + "sm.samuraiYear="+y
                    if years[-1] != y:
                        q1 = q1 + " or "
                q1 = q1 + ")"
        else:
            q1 = q1 + " and samuraiYear is null"
        if (replacementState == "1"):
            q1 += " and (sp.product <> IFNULL(sp3.product,sp2.product))"
        elif (replacementState == "2"):
            q1 += " and (sp.product = IFNULL(sp3.product,sp2.product))"
        if (filterPlanner != "2"):
            q1 = q1 + " and planner="+filterPlanner
        if (site != "" and site != None):
            q1 = q1 + " and sm.location in (select sl2.id from samurai_sites sl2 where id="+str(site)+" or remap_id="+str(site)+")"
        if (region != "" and region != None):
            q1 = q1 + " and srg.id="+str(region)
        if (not olderThan is None and olderThan != "0" and olderThan != ""):
            if int(olderThan)>0:
                q1 = q1 + " and lastSeen<date_sub(now(), interval "+olderThan+" day)"
            if int(olderThan)<0:
                q1 = q1 + " and lastSeen>date_sub(now(), interval "+str(abs(int(olderThan)))+ " day)"
        if (not version is None and version != ""):
            q1 += " and sm.version like '%"+version+"%'"
        if (not deviceModel is None) and (deviceModel != ""):
            q1 = q1 + " and ("
            if not exact:
                for deviceModel in deviceModels:
                    q1 = q1 + "sp.product like '%"+deviceModel+"%'"
                    if deviceModels[-1] != deviceModel:
                        q1 = q1 + " or "
            else:
                q1 = q1 + "sp.product = '"+deviceModel+"'"
            q1 = q1 + ")"
        if (not deviceNew is None) and (deviceNew != ""):
            q1 = q1 + " and ("
            for deviceNew in deviceNews:
                q1 = q1 + "sp3.product like '%"+deviceNew+"%'" + " or "+"sp2.product like '%"+deviceNew+"%'"
                if deviceNews[-1] != deviceNew:
                    q1 = q1 + " or "
            q1 = q1 + ")"
        if not budgetSource is None:
            q1 = q1 + " and ("
            for budgetSource in budgetSources:
                q1 = q1 + "ss2.id="+budgetSource
                if budgetSources[-1] != budgetSource:
                    q1 = q1 + " or "
            q1 = q1 + ")" 
        if (not deviceName is None) and (deviceName != ""):
            q1 = q1 + " and sm.name like '%"+deviceName+"%'"
        if not orderBy is None:
            qorder = " order by "+orderBy
        else:
            qorder = ""
        qlimit = " limit "+str(start)+","+str(page)
        sql_query = query1 + q1 + qorder + qlimit
        print (sql_query)
        query = s.query(sql_query)
        result1 = s.getAllRows(query)
        sql_query = "select count(*) as tr, sum(CASE when sm.newCapital is not null then sm.newCapital*srg.factor when sp3.capital is not null then sp3.capital*srg.factor else sp2.capital*srg.factor end) as total" + q1
        print (sql_query)
        query = s.query(sql_query)
        result2 = s.getAllRows(query)

        qs = parse_qs(request.query_string, keep_blank_values=True)
        syslog.info(qs)
#        if sys.version_info[0] >= 3.10 and query_string:
#            query_string.get(b"start").pop(0)
#        else:
#            query_string.pop("start", True)
        if qs and b"start" in qs:
            del qs[b"start"]
        syslog.info(qs)
        new_query_string = urlencode(qs,doseq=True)
        syslog.info(new_query_string)

        fy = []
        for i in range(10):
            fy.append("FY'"+str(i+23)+" (previously FY'"+str(i+23-5)+")")
#    fy = ["FY'23","FY'24","FY'25","FY'26","FY'22 or FY'27","FY'23 or FY'28","FY'24 or FY'29","FY'25 or FY'30","FY'26 or FY'31","FY'27 or FY'32"]
        if notAssigned:
            year="N"
        if snFilter is None: snFilter = ""
        if version is None: version = ""
        
        rowCount = result2[0]["tr"]
        if start>rowCount:
            args = request.args.copy()
            args["start"]=0
            return redirect("{}?{}".format(request.path,urlencode(args)),
                    code=301)
        pages = [i//page for i in range(0,rowCount,page)]
        navPages1=[]
        navPages2=[]
        if len(pages) > 10:
            if (start//page) > 5 and (start//page)+5<(rowCount//page):
                navPages1.append(pages[0])
                for i in range((start//page)-5, (start//page)+5):
                    navPages1.append(pages[i])
                for i in range(len(pages)-10,len(pages)):
                    navPages2.append(pages[i])
            else:
                if (start//page) > 5:
                    navPages1.append(pages[0])
                    for i in range((start//page)-5,len(pages)):
                        navPages1.append(pages[i])
                    navPages2 = []
                else:
                    if (rowCount//page)>(start//page)+5:
                        navPages1.append(pages[0])
                        for i in range(start//page,(start//page)+5):
                            navPages1.append(pages[i])
                        for i in range(len(pages)-10,len(pages)):
                            navPages2.append(pages[i])
                    else:
                        navPages1.append(pages[0])
                        for i in range((start//page),len(pages)):
                            navPages1.append(pages[i])
                        navPages2 = []
        else:
            navPages1 = pages[:]
            navPages2 = []
        navPagesTemp = navPages1[:]
        navPages1 = []
        for item in navPagesTemp:
            if item not in navPages1:
                navPages1.append(item)
        navPages2 = [e for e in navPages2 if e not in navPages1]

        return render_template('samurai.html', auth=get_auth(), task=task, site=site, region=region,
            start=start, stop=stop, page=page, samuraiData=result1,
            display_order=display_order,
            planners=planners,
            filterPlanner=filterPlanner,
            plannerDisplayOrder=planner_display_order,
            dollar=dollar,
            formatDollar=formatDollar,
            rowCount=result2[0]["tr"],
            navPages1=navPages1,
            navPages2=navPages2,
            filteredCapital=result2[0]["total"],
            new_query_string=new_query_string,
            replaceQueryString=replaceQueryString,
            deviceNameInput=deviceName,
            deviceModelInput=deviceModel,
            deviceNewInput=deviceNew,
            snFilterInput=snFilter,
            filterCapital=capital,
            versionInput=version,
            fy=fy,
            ipaddressInput=ipaddress,
            macaddressInput=macaddress,
            endofsaleInput=end_of_sale,
            endofsupportInput=end_of_support,
            dbSource=dbSource,
            thisYear=thisYear,
            exportExcel=exportToExcel,
            replaceSortOrder=replaceSortOrder,
            overrideProducts=overrideProducts,
            regions=regions,
            sites=sites,
            states=states,
            year=year,
            budgetSource=budgetSource,
            state=state,
            replacementState=replacementState,
            olderThan=olderThan,
            sources=sources,
            today=today)

@app.route("/change_log", methods=['GET'])
@login_required
def load_change_audit_log_page():
    return render_template('change_audit_log.html', auth=get_auth())

@app.route("/change_log/<task>", defaults={'id': None}, methods=['GET'])
@app.route("/change_log/<task>", defaults={'id': None}, methods=['POST'])
@app.route("/change_log/<task>/<id>", methods=['GET', 'PUT', 'DELETE'])
@login_required
def change_audit_log_api(task="", id=""):
    """
        Returns a list of dictionaries formatted like this:
        {
            "affected_systems": "All production Edgeconnect routers",
            "archived": 0,
            "archived_by": "",
            "archived_reason": "",
            "archived_time": null,
            "change_log": "Edgeconnect software upgrade",
            "created_time": "2024-09-10 10:48",
            "crq": "CHG3492502-1",
            "environment": 0,
            "id": 5,
            "modification_reason": "",
            "modified": 0,
            "modified_by": "",
            "modified_time": null,
            "original_id": 4,
            "resource_id": 1,
            "site": "",
            "submitted_by": "g528525",
            "team": "Network",
            "team_group": "SDWAN"
        }
	"""
    # team_list is a variable that controls the team db column.  If we every open this up to other teams this list will need to be adjusted.
    # We will also need to add to the team_groups on the client side.
    team_list = ['Network', 'Platform']
    schema = ChangeAuditLogSchema(many=True)

    # GET /change_log/getData?sort=[asc|desc]
    # Determine the created_time sort order based on the parameter
    sort = request.args.get('sort', "desc", type=str)
    if sort == "asc":
        sort_order = asc(ChangeAuditLog.created_time)
    else:
        sort_order = desc(ChangeAuditLog.created_time)

    if task == "getData":
        if id == None:
            try:
                #This returns every non-archived and most recent modified item from the change_audit_log table and
                #by default returns them in reverse chronological order
                log_entries = ChangeAuditLog.query.filter_by(modified=0, archived=0).order_by(sort_order).all()
                results = schema.dump(log_entries)
                for result in results:
                    #present the date in a nicer format
                    from_iso_time = datetime.datetime.fromisoformat(result['created_time'])
                    result['created_time'] = from_iso_time.strftime("%Y-%m-%d %H:%M")
                return jsonify(results), 200
            except Exception as e:
                print("There was an error retrieving the change log data", e)
                return jsonify({"error: ": "There was an error retrieving the data",
                                "message": str(e)}),500
            finally:
                sdb.session.close()
        elif id == "archived":
            try:
                #This returns every archived item from the change_audit_log table
                archived_log_entries = ChangeAuditLog.query.filter_by(archived=1).order_by(sort_order).all()
                #print("***************** Archived entries: ", archived_log_entries)
                results = schema.dump(archived_log_entries)
                return jsonify(results), 200
            except Exception as e:
                print("There was an error retrieving the change log data", e)
                return jsonify({"error: ": "There was an error retrieving the data",
                                "message": str(e)}),500
            finally:
                sdb.session.close()
        elif id == "all":
            try:
                #This returns every item from the change_audit_log table
                all_log_entires = ChangeAuditLog.query.order_by(sort_order).all()
                results = schema.dump(all_log_entires)
                return jsonify(results), 200
            except Exception as e:
                print("There was an error retrieving the change log data", e)
                return jsonify({"error: ": "There was an error retrieving the data",
                                "message": str(e)}),500
            finally:
                sdb.session.close()
        else:
            return jsonify({"error": "Invalid filter"}), 400
    elif task == "getModifyChain":
        #This returns all previous entries in the sequence of modification for an entry id
        if request.method == "GET":
            try:
                #Should archived=1 be excluded here?
                entry_to_check  = ChangeAuditLog.query.filter_by(id=id).first()
                modified_entry_chain = []
                #Check if the entry was found
                if not entry_to_check:
                    raise ValueError(f"Log entry {id} not found")
                
                #Check if the entry has been modified (original_id != Null)
                if entry_to_check.original_id:
                    OID = entry_to_check.original_id
                    while OID:
                        original_message = ChangeAuditLog.query.filter_by(id=OID).first()
                        modified_entry_chain.append(original_message)
                        if original_message.original_id:
                            OID = original_message.original_id
                        else:
                            OID = None
                    results = schema.dump(modified_entry_chain)
                    #Clean up data for output
                    for result in results:
                        #Change environment from 0/1 to PROD/NON-PROD
                        if result['environment'] == 0:
                            result['environment'] = "Prod"
                        else:
                            result['environment'] = "Non-Prod"
                        #Remove the T in the ISO date format
                        created_from_iso_time = datetime.datetime.fromisoformat(result['created_time'])
                        modified_from_iso_time = datetime.datetime.fromisoformat(result['modified_time'])
                        result['created_time'] = created_from_iso_time.strftime("%Y-%m-%d %H:%M")
                        result['modified_time'] = modified_from_iso_time.strftime("%Y-%m-%d %H:%M")
                    return jsonify(results), 200
                else:
                    raise ValueError(f"Log entry {id} is not a child entry of an entry that has been modified")
            except ValueError as ve:                
                print("Error with log entry: ", str(ve))
                return jsonify({"error": "Log entry error", 
                                "message": str(ve)}), 400
            except Exception as e:
                print("Error with log entry: ", e)
                return jsonify({"error": "There was an error retrieving the data",
                                "message": str(e)}),500
            finally:
                sdb.session.close()
        else:
            return jsonify({"error": "Invalid method"}), 400
    elif task == "updateData":
        #modify existing log entry
        if request.method == 'PUT':
            try:
                entry_to_modify = ChangeAuditLog.query.filter_by(id=request.json['id']).first()
                
                # Check if the entry was found
                if not entry_to_modify:
                    raise ValueError(f"Log entry {request.json['id']} not found")

                #modified_time and flag
                entry_to_modify.modified_time = datetime.datetime.now(ZoneInfo('America/Chicago'))
                entry_to_modify.modified = 1

                #required fields
                if 'modified_by' in request.json and request.json['modified_by'] is not None:
                    entry_to_modify.modified_by = request.json['modified_by']
                else:
                    raise ValueError(f"The 'modified_by' attribute is required and must not be empty")
                if 'modification_reason' in request.json and request.json['modification_reason'] is not None and request.json['modification_reason'] != "":
                    entry_to_modify.modification_reason = request.json['modification_reason']
                else:
                    raise ValueError(f"The 'modification_reason' attribute is required and must not be empty")
                
                #create new log entry with changes and point to the original
                new_modified_entry = ChangeAuditLog()

                #point at the original entry
                new_modified_entry.original_id = entry_to_modify.id
                #copy from the original entry
                new_modified_entry.created_time = entry_to_modify.created_time
                new_modified_entry.resource_id = entry_to_modify.resource_id
                #update with modified data
                #required fields
                if 'team' in request.json and request.json['team'] in team_list:
                    new_modified_entry.team = request.json['team']
                else:
                    raise ValueError(f"The 'team' attribute is required and must be one of {', '.join(team_list)}.")
                if 'environment' in request.json and request.json['environment'] in [0,1]:
                    new_modified_entry.environment = request.json['environment']
                else:
                    raise ValueError("The 'environment' attribute is required and must be either 0 or 1.")
                if 'change_log' in request.json and request.json['change_log'] is not None:
                    new_modified_entry.change_log = request.json['change_log']
                else:
                    raise ValueError("The 'change_log' attribute is required and must not be empty.")
                if 'submitted_by' in request.json and request.json['submitted_by'] is not None:
                    new_modified_entry.submitted_by = str(request.json['submitted_by'])
                else:
                    raise ValueError("The 'submitted_by' attribute is required and must not be empty.")
                if 'team_group' in request.json and request.json['team_group'] is not None:
                    new_modified_entry.team_group = request.json['team_group']
                else:
                    raise ValueError(f"The 'team_group' attribute is required and must not be empty.")
                #optional fields
                if 'site' in request.json and request.json['site'] is not None:
                    new_modified_entry.site = request.json['site']
                if 'affected_systems' in request.json and request.json['affected_systems'] is not None:
                    new_modified_entry.affected_systems = request.json['affected_systems']
                if 'crq' in request.json and request.json['crq'] is not None:
                    new_modified_entry.crq = request.json['crq']

                sdb.session.add(new_modified_entry)
                #commit all changes
                sdb.session.commit()
                return jsonify({"message": "Log entry updated successfully"}), 201
            
            except ValueError as ve:
                sdb.session.rollback()
                print("Error updating a log entry: ", str(ve))
                return jsonify({"error": "Failed to update log entry", 
                                "message": str(ve)}), 400
            except Exception as e:
                sdb.session.rollback()
                print("Error updating a log entry: ", str(e))
                return jsonify({"error": "Failed to update log entry", 
                                "message": str(e)}), 500
            finally:
                sdb.session.close()

        #create new log entry
        elif request.method == 'POST':
            try:
                entry_to_add = ChangeAuditLog()

                #resource_id will equal 1 for now - this code will need to be more dynamic when we introduce the RBAC system
                entry_to_add.resource_id = 1
                #created_time
                entry_to_add.created_time = datetime.datetime.now(ZoneInfo('America/Chicago'))
                #required fields
                if 'team' in request.json and request.json['team'] in team_list:
                    entry_to_add.team = request.json['team']
                else:
                    raise ValueError(f"The 'team' attribute is required and must be one of {', '.join(team_list)}.")
                if 'environment' in request.json and request.json['environment'] in [0,1]:
                    entry_to_add.environment = request.json['environment']
                else:
                    raise ValueError("The 'environment' attribute is required and must be either 0 or 1.")
                if 'change_log' in request.json and request.json['change_log'] is not None:
                    entry_to_add.change_log = request.json['change_log']
                else:
                    raise ValueError("The 'change_log' attribute is required and must not be empty.")
                if 'submitted_by' in request.json and request.json['submitted_by'] is not None:
                    entry_to_add.submitted_by = str(request.json['submitted_by'])
                else:
                    raise ValueError("The 'submitted_by' attribute is required and must not be empty.")
                if 'team_group' in request.json and request.json['team_group'] is not None:
                    entry_to_add.team_group = request.json['team_group']
                else:
                    raise ValueError(f"The 'team_group' attribute is required and must not be empty.")
                #optional fields
                if 'site' in request.json and request.json['site'] is not None:
                    entry_to_add.site = request.json['site']
                if 'affected_systems' in request.json and request.json['affected_systems'] is not None:
                    entry_to_add.affected_systems = request.json['affected_systems']
                if 'crq' in request.json and request.json['crq'] is not None:
                    entry_to_add.crq = request.json['crq']

                sdb.session.add(entry_to_add)
                sdb.session.commit()

                return jsonify({"message": "Log entry created successfully"}), 201
            except ValueError as ve:
                sdb.session.rollback()
                print("Error adding a new log entry: ", str(ve))
                return jsonify({"error": "Failed to add a new log entry", 
                                "message": str(ve)}), 400
            except Exception as e:
                sdb.session.rollback()
                print("Error adding a new log entry: ", str(e))
                return jsonify({"error": "Failed to add a new log entry", 
                                "message": str(e)}), 500
            finally:
                sdb.session.close()

    elif task == "archiveData":
        if request.method == 'PUT':
            '''
                This method sets archived to 1 and adds the archived_by and archived_reason attributes.  It also removes this row from the default
                'GET' API view essentially "deleting" it.
            '''
            try:
                entry_to_archive = ChangeAuditLog.query.filter_by(id=request.json['id']).first()
            
                # Check if the entry was found
                if not entry_to_archive:
                    raise ValueError(f"Log entry {request.json['id']} not found")

                #archived_time and flag
                entry_to_archive.archive_time = datetime.datetime.now(ZoneInfo('America/Chicago'))
                entry_to_archive.archived = 1

                #required fields
                if 'archived_by' in request.json and request.json['archived_by'] is not None:
                    entry_to_archive.archived_by = request.json['archived_by']
                else:
                    raise ValueError(f"The 'archived_by' attribute is required and must not be empty")
                if 'archived_reason' in request.json and request.json['archived_reason'] is not None and request.json['archived_reason'] != "":
                    entry_to_archive.archived_reason = request.json['archived_reason']
                else:
                    raise ValueError(f"The 'archived_reason' attribute is required and must not be empty")
                
                sdb.session.commit()
                return jsonify({"message": "Log entry archived successfully"}), 201
            
            except ValueError as ve:
                sdb.session.rollback()
                print("Error deleting a log entry: ", str(ve))
                return jsonify({"error": "Failed to archive log entry", 
                                "message": str(ve)}), 400
            except Exception as e:
                sdb.session.rollback()
                print("Error deleting a log entry: ", str(e))
                return jsonify({"error": "Failed to archive log entry", 
                                "message": str(e)}), 500
            finally:
                sdb.session.close()
    else:
        return jsonify({"Result": "Invalid task"}), 400

@app.route("/samurai/region_info", methods=['GET'])
@login_required
def get_samurai_region_info():
    """
        Returns all of the data from the samurai_regions table
    """
    try:                
        region_schema = SamuraiRegionsSchema(many = True)
        region_info = sdb.session.query(SamuraiRegions).order_by(SamuraiRegions.name.asc()).all()
        region_list = region_schema.dump(region_info)        
        
        return jsonify(region_list),200
    except Exception as e:
        print("Get samurai region data api error: ", str(e))
        return jsonify({"Result: ": "There was an error retrieving the data",
                        "Error Message": str(e)}),500
    finally:
        sdb.session.close()
@app.route("/samurai/samurai_sites", methods=['GET'])
@login_required
def load_samurai_sites_page():
    #loads the Samurai sites page
    return render_template('samurai_sites.html', auth=get_auth())

@app.route("/samurai/sites_info/<task>", methods=['GET', 'POST'])
@app.route("/samurai/sites_info/<task>/<id>", methods=['PUT', 'DELETE'])
@login_required
def get_samurai_sites_info(task="", id=""):
    """
        Returns a list of dictionaries formatted like this:
        {
        "id": 137,
        "lat": 44.976,
        "lng": -93.3963,
        "location": "MGO",
        "region": 1,
        "remap_id": 179,
        "state": 0
        }
    """
    site_schema = SamuraiSitesSchema(many = True)
    
    if task == "getData":
        # GET /samurai/sites_info/getData?sort=[asc|desc]
        # Determine the sort order based on the parameter
        sort = request.args.get('sort', "asc", type=str)
        if sort == "asc":
            sort_order = asc(SamuraiSites.location)
        else:
            sort_order = desc(SamuraiSites.location)
        
        try:
            sites_info = sdb.session.query(SamuraiSites).order_by(sort_order).all()
            sites_list = site_schema.dump(sites_info)
            return jsonify(sites_list),200
        except Exception as e:
            print("Get samurai sites data api error: ", str(e))
            return jsonify({"Result: ": "There was an error retrieving the data",
                            "Error Message": str(e)}),500
        finally:
            sdb.session.close()
    elif task == "updateData":
            if request.method == "PUT":
                #update existing site
                #at this time we are only allowing an update to the region of a site
                if id:
                    try:
                        site_to_update = sdb.session.query(SamuraiSites).filter_by(id=id).first()  

                        region_id_info = sdb.session.query(SamuraiRegions.id).all()
                        region_id_list = [region_id[0] for region_id in region_id_info]
                        
                        if site_to_update:                            
                            if 'region' in request.json and request.json['region'] is not None:
                                if request.json['region'] not in region_id_list:
                                    raise ValueError("Region not found")
                                site_to_update.region = request.json['region']
                            sdb.session.commit()

                            return jsonify({"Result": "Site region updated successfully"}),200
                        else:
                            return jsonify({"Error": "Site not found"}),404
                    except Exception as e:
                        print("Error updating device type: ", str(e))
                        return jsonify({"Error": "Failed to update device type",
                                        "Error Message": str(e)}),500
                    finally:
                        sdb.session.close()    
                else:
                    return jsonify({"Error:": "Required id missing"}), 400
                
            elif request.method == "POST":
                #create new site record
                #location (site mnemonic) and region are required fields
                #lat and lng are optional fields
                try:                    
                    if 'location' in request.json and request.json['location'] is not None and 'region' in request.json and request.json['region'] is not None:                                        
                        # Validate that the specified region exists
                        region_exists = sdb.session.query(SamuraiRegions.id).filter_by(id=request.json['region']).first()
                        if not region_exists:
                            return jsonify({"Error": "Invalid region ID"}), 400
                        
                        site_to_add = SamuraiSites(
                            location = request.json['location'],
                            region = request.json['region'],
                            lat = request.json.get('lat'),
                            lng = request.json.get('lng')
                        )
                        sdb.session.add(site_to_add)
                        sdb.session.commit()
                        return jsonify({"Result": "Samurai site created successfully"}),200
                    else:
                        return jsonify({"Error": "Data error - location and region fields cannot be empty"}),400
                except Exception as e:
                    print("Error adding new samurai site: ", e)
                    return jsonify({"Error": "Failed to add new site",
                                    "Error Message": str(e)}),500
                finally:
                    sdb.session.close()
            
            elif request.method == "DELETE":
                #delete device type record
                if id:
                    return jsonify({"Error: ": "Method not built yet"}),405
                else:
                    return jsonify({"Error: ": "Required id missing"}),500
                
@app.route("/samurai/manage_products", methods=['GET'])
@login_required
def load_samurai_manage_products_page():
    #loads the Samurai Manage Products page
    return render_template('samurai_manage_products.html', auth=get_auth())

@app.route("/samurai/device_types", methods=['GET'])
@login_required
def load_samurai_device_type_page():
    #loads the Samurai Device Type page
    return render_template('samurai_device_types.html', auth=get_auth())

@app.route("/samurai/device_types/<task>", methods=['GET', 'POST'])
@app.route("/samurai/device_types/<task>/<id>", methods=['PUT', 'DELETE'])
@login_required
def load_device_type_info(task="", id=""):
    """
        Returns a list of dictionaries formatted like this:
        {
            "id": 2,
            "deviceType": "Switch"
        }
    """
    if task == "getData":
        try:
            db_devicetype_list = sdb.session.query(SamuraiDeviceTypes).all()
            devicetype_schema = SamuraiDeviceTypesSchema(many = True)
            devicetype_list = devicetype_schema.dump(db_devicetype_list)
            
            if sys.version_info[0] > 2:
                sorted_devicetype_list = devicetype_list
            else:
                sorted_devicetype_list = devicetype_list.data
               
            #Sort alphabetically by device type
            sorted_devicetype_list = sorted(sorted_devicetype_list, key=lambda x: x["deviceType"], reverse=False)
            return jsonify(sorted_devicetype_list),200
        except Exception as e:
            print("Get device type data api error: ", str(e))
            return jsonify({"Result: ": "There was an error retrieving the data",
                            "Error Message": str(e)}),500
        finally:
            sdb.session.close()

    elif task == "updateData":
            if request.method == "PUT":
                #update existing device type
                if id:
                    try:
                        devicetype_to_update = sdb.session.query(SamuraiDeviceTypes).filter_by(id=id).first()  

                        if devicetype_to_update:
                            if 'deviceType' in request.json and request.json['deviceType'] is not None:
                                devicetype_to_update.deviceType = request.json['deviceType']
                            sdb.session.commit()

                            return jsonify({"Result": "Device Type updated successfully"}),200
                        else:
                            return jsonify({"Error": "Device Type not found"}),404
                    except Exception as e:
                        print("Error updating device type: ", str(e))
                        return jsonify({"Error": "Failed to update device type",
                                        "Error Message": str(e)}),500
                    finally:
                        sdb.session.close()    
                else:
                    return jsonify({"Error:": "Required id missing"}), 400
                
            elif request.method == "POST":
                #create new device type record
                try:
                    if 'deviceType' in request.json and request.json['deviceType'] is not None:
                        devicetype_to_add = SamuraiDeviceTypes(deviceType=request.json['deviceType'])
                        sdb.session.add(devicetype_to_add)
                        sdb.session.commit()
                        return jsonify({"Result": "Device Type created successfully"}),200
                    else:
                        return jsonify({"Error": "Data error - Device type field cannot be empty"}),400
                except Exception as e:
                    print("Error adding new device type: ", e)
                    return jsonify({"Error": "Failed to add new device type",
                                    "Error Message": str(e)}),500
                finally:
                    sdb.session.close()
            
            elif request.method == "DELETE":
                #delete device type record
                if id:
                    return jsonify({"Error: ": "Method not built yet"}),405
                else:
                    return jsonify({"Error: ": "Required id missing"}),500

@app.route("/samurai/vendors", methods=['GET'])
@login_required
def load_samurai_vendors_page():
    #loads the Samurai Vendors page
    return render_template('samurai_vendors.html', auth=get_auth())

@app.route("/samurai/vendor_info/<task>", methods=['GET', 'POST'])
@app.route("/samurai/vendor_info/<task>/<id>", methods=['PUT', 'DELETE'])
@login_required
def load_vendor_info(task="", id=""):
    """
        Returns a list of dictionaries formatted like this:
        {
            "id": 1,
            "vendor": "Aruba"
        }
    """
    if task == "getData":
        try:
            db_vendor_list = sdb.session.query(SamuraiVendors).all()
            vendor_schema = SamuraiVendorsSchema(many = True)
            vendor_list = vendor_schema.dump(db_vendor_list)
            #if you print vendor_list you get:
            #('vendor list: ', MarshalResult(data=[{u'vendor': u'Aruba', u'id': 1}, {u'vendor': u'Cisco', u'id': 2}], errors={}))
            #so we want to just return the data portion otherwise I get a second empty {} in the results
            #also sort alphabetically by vendor name
            if sys.version_info[0] > 2:
                sorted_vendor_list = vendor_list
            else:
                sorted_vendor_list = vendor_list.data

            sorted_vendor_list = sorted(sorted_vendor_list, key=lambda x: x["vendor"], reverse=False)

            return jsonify(sorted_vendor_list),200
        except Exception as e:
            print("Get vendor data api error: ", str(e))
            return jsonify({"Result: ": "There was an error retrieving the data",
                            "Error Message": str(e)}),500
        finally:
            sdb.session.close()
    elif task == "updateData":
        if request.method == "PUT":
            #update existing vendor
            if id:
                try:
                    vendor_to_update = sdb.session.query(SamuraiVendors).filter_by(id=id).first()  

                    if vendor_to_update:
                        if 'vendor' in request.json and request.json['vendor'] is not None:
                            vendor_to_update.vendor = request.json['vendor']

                        sdb.session.commit()
                        return jsonify({"Result": "Vendor updated successfully"}),200
                    else:
                        return jsonify({"Error": "Vendor not found"}),404
                except Exception as e:
                    print("Error updating vendor: ", str(e))
                    return jsonify({"Error": "Failed to update vendor",
                                    "message": str(e)}),500
                finally:
                    sdb.session.close()    
            else:
                return jsonify({"Error:": "Required id missing"}),400
            
        elif request.method == "POST":
            #create new vendor record
            try:
                if 'vendor' in request.json and request.json['vendor'] is not None:
                    vendor_to_add = SamuraiVendors(vendor=request.json['vendor'])
                    sdb.session.add(vendor_to_add)
                    sdb.session.commit()
                    return jsonify({"Result": "Vendor created successfully"}),200
                else:
                    return jsonify({"Error": "Data error - Vendor field cannot be empty"}),400
            except Exception as e:
                print("Error adding new vendor: ", str(e))
                return jsonify({"Error": "Failed to add new vendor",
                                "message": str(e)}),500
            finally:
                sdb.session.close()
        
        elif request.method == "DELETE":
            #delete vendor record
            if id:
                return jsonify({"Error: ": "Method not built yet"}),405
            else:
                return jsonify({"Error: ": "Required id missing"}),500
                

@app.route("/samurai/products", methods=['GET'])
@login_required
def load_samurai_products_page():
    #loads the Samurai Products page
    return render_template('samurai_products.html', auth=get_auth())

@app.route("/samurai/products/<task>", defaults={'filter': None}, methods=['GET'])
@app.route("/samurai/products/<task>/<filter>", methods=['GET'])
@app.route("/samurai/products/<task>", defaults={'id': None}, methods=['POST'])
@app.route("/samurai/products/<task>/<id>", methods=['PUT', 'DELETE'])
@login_required
def samurai_load_products(task="", id="", filter=""):
    """
        Returns a list of dictionaries formatted like this:
        {
            "announcement": "https://www.cisco.com/c/en/us/products/collateral/interfaces-modules/transceiver-modules/10gbase-sr-sfp-module-extend-temp-range-eol.html#:~:text=Cisco%20announces%20the%20end%2Dof,)%20is%20February%2014%2C%202023.",
            "capital": 375,
            "current": true,
            "deviceType": 5,
            "deviceType_name": "SFP",
            "end_of_hw_renew": "2027-05-15",
            "end_of_hw_support": "2028-02-29",
            "end_of_sale": "2028-06-01",
            "end_of_support": "2028-02-29",
            "end_of_sw_sec_upd": null,
            "expMaint": 0,
            "expOther": 0,
            "expSaas": 0,
            "discovered": 0,
            "id": 178,
            "maint1Description": "",
            "maint1ProductNumber": "",
            "maint2Description": "",
            "maint2ProductNumber": "",
            "modelNumber": "test1234",
            "product": "10Gbase-SR",
            "productAlias": "10Gbase-SR",
            "productLink": "",
            "productNotes": "test notes\n\n\n\nBlah blah\nhehe\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nDoh!\n",
            "productType": 1,
            "usageCount": 76,
            "vendor_id": 2,
            "vendor_name": "Cisco"

            The filter attribute on the GET method can be used like this:
                No filter used = GET returns all rows
                "/NoStatic" = GET all rows except discovered = 2
                "/Satic" = GET all rows where discovered = 2
                "/Discovered" = GET all rows where discovered = 0
                "/Custom" = GET all rows where discovered = 1
        }
    """
    if task == "getData":
        try:
            #This returns every item from the samurai products table along with its usage count from the samurai master table
            #Also filters out any rows in the db where product = "" and discovered !=0
            
            query = (
                sdb.session.query(
                    SamuraiProducts,
                    func.count().label('total'),
                    SamuraiVendors.vendor,
                    SamuraiDeviceTypes.deviceType
                )
                .join(SamuraiMaster, SamuraiMaster.model == SamuraiProducts.id)
                .join(SamuraiVendors, SamuraiVendors.id == SamuraiProducts.vendor)
                .join(SamuraiDeviceTypes, SamuraiDeviceTypes.id == SamuraiProducts.deviceType)
                .filter((SamuraiMaster.state == 0) | (SamuraiMaster.state.is_(None)))
                .filter(SamuraiProducts.product != "")
                .filter(SamuraiProducts.discovered == 0)
                .group_by(SamuraiProducts.product)
            )            
            #find custom products only
            query_custom = (
                sdb.session.query(
                    SamuraiProducts,
                    sdb.text('0'),
                    SamuraiVendors.vendor,
                    SamuraiDeviceTypes.deviceType
                )
                .join(SamuraiVendors, SamuraiVendors.id == SamuraiProducts.vendor)
                .join(SamuraiDeviceTypes, SamuraiDeviceTypes.id == SamuraiProducts.deviceType)
                .filter(SamuraiProducts.product != "")
                .filter(SamuraiProducts.discovered == 1)
                .group_by(SamuraiProducts.product)
            )

            results = query.all()
            results_custom = query_custom.all()
            #put the two results together
            results += results_custom

            output_list = []
            data_fields = ['id', 'product', 'capital', 'expMaint', 'expSaas', 'expOther', 'current', 'deviceType',
                           'productType', 'vendor', 'announcement', 'productAlias', 'modelNumber', 'productLink',
                           'productNotes', 'maint1PartNumber', 'maint1Description', 'maint2PartNumber', 'maint2Description',
                           'discovered', 'end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 'end_of_support']
            date_fields = ['end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 'end_of_support']
            #results is a tuple (SamuraiProducts, SamuraiMaster count, SamuraiVendors vendor, SamuraiDeviceTypes deviceType) based on the join
            for result, count, vendor, deviceType in results:
                row_dict = {}
                for data_field in data_fields:
                    #need to account for vendor becuase I didn't use the db table name as the attribute for the dictionary
                    if data_field == "vendor":
                        row_dict['vendor_id'] = getattr(result, "vendor")
                    else:
                        row_dict[data_field] = getattr(result, data_field)
                #modify the date fields to only show the year month and date
                for date_field in date_fields:
                    #Need to skip over each if it is empty
                    if row_dict[date_field]:
                        try:
                            row_dict[date_field] = row_dict[date_field].strftime('%Y-%m-%d')
                            # this is a valid date in the database stored as YYYY-MM-DD
                        except:
                            row_dict[date_field] = ""
                row_dict['usageCount'] = count
                row_dict['vendor_name'] = vendor
                row_dict['deviceType_name'] = deviceType
                output_list.append(row_dict)

            sorted_output_list = sorted(output_list, key=lambda x: (not x['current'], x['productAlias']))

            return jsonify(sorted_output_list),200

        except Exception as e:
            print("***************************Error fetching data: ", str(e))
            return jsonify({"error": "Failed to fetch data",
                            "error message": str(e)}),500
        
        finally:
            sdb.session.close()
    elif task == "getFilteredData":
        try:
            if filter:
                if filter.lower() == "discovered":
                    get_filter = 0
                elif filter.lower() == "custom":
                    get_filter = 1
                elif filter.lower() == "static":
                    get_filter = 2
                elif filter.lower() == "nostatic":  #discovered and custom products
                    get_filter = 3
                else:
                    get_filter = 99
            else:
                get_filter = 99

            query = (
                sdb.session.query(
                    SamuraiProducts,
                    SamuraiVendors.vendor,
                    SamuraiDeviceTypes.deviceType
                )             
            .join(SamuraiVendors, SamuraiVendors.id == SamuraiProducts.vendor)
            .join(SamuraiDeviceTypes, SamuraiDeviceTypes.id == SamuraiProducts.deviceType)
            .filter(SamuraiProducts.product != "")
            )

            if get_filter in [0,1,2]:
                query = query.filter(SamuraiProducts.discovered == get_filter)
            elif get_filter == 3:
                query = query.filter(SamuraiProducts.discovered != 2)

            results = query.all()

            output_list = []
            data_fields = ['id', 'product', 'capital', 'expMaint', 'expSaas', 'expOther', 'current', 'deviceType',
                           'productType', 'vendor', 'announcement', 'productAlias', 'modelNumber', 'productLink',
                           'productNotes', 'maint1PartNumber', 'maint1Description', 'maint2PartNumber', 'maint2Description',
                           'discovered', 'end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 'end_of_support']
            date_fields = ['end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 'end_of_support']

            #results is a tuple (SamuraiProducts, SamuraiVendors vendor, SamuraiDeviceTypes deviceType) based on the join
            for result, vendor, deviceType in results:
                row_dict = {}
                #grab all of the attributes from result and put them in the dictionary
                for data_field in data_fields:
                    #need to account for vendor becuase I didn't use the db table name as the attribute for the dictionary
                    if data_field == "vendor":
                        row_dict['vendor_id'] = getattr(result, "vendor")
                    else:
                        row_dict[data_field] = getattr(result, data_field)
                #modify the date fields to only show the year month and date
                for date_field in date_fields:
                    #Need to skip over each if it is empty
                    if row_dict[date_field]:
                        try:
                            row_dict[date_field] = row_dict[date_field].strftime('%Y-%m-%d')
                            #this is a valid date stored in the DB as YYYY-MM-DD
                        except:
                            row_dict[date_field] = ""
                row_dict['vendor_name'] = vendor
                row_dict['deviceType_name'] = deviceType
                output_list.append(row_dict)

            sorted_output_list = sorted(output_list, key=lambda x: (x['product']))

            return jsonify(sorted_output_list),200

        except Exception as e:
            print("***************************Error fetching data: ", str(e))
            return jsonify({"error": "Failed to fetch data",
                            "error message": str(e)}),500
        
        finally:
            sdb.session.close()
    elif task == "updateData":
        if request.method == 'PUT':
            try:
                product_to_update = sdb.session.query(SamuraiProducts).filter_by(id=id).first()  
                
                if product_to_update:
                    #product field should not be edited
                    #discovered field should not be edited
                    data_fields = ['capital', 'expOther', 'expSaas', 'expMaint', 'current', 'deviceType', 'vendor',
                                   'productAlias', 'modelNumber', 'maint1PartNumber', 'maint1Description', 'maint2PartNumber',
                                   'maint2Description', 'productType', 'announcement', 'productLink', 'productNotes',
                                   'end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 
                                   'end_of_support']
                    date_fields = ['end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 'end_of_support']
                    for data_field in data_fields:
                        if data_field in request.json and request.json[data_field] is not None and request.json[data_field] != "":
                            #print(f"*-*-*-*-*-*-*-*-*-*-*-*-*-*-* The input for {data_field} is [{request.json[data_field]}]")
                            if data_field in date_fields:
                                #validate the given dates are in the right format, if not throw and error
                                try:
                                    datetime.datetime.strptime(request.json[data_field], '%Y-%m-%d')
                                    setattr(product_to_update, data_field, request.json[data_field])
                                except ValueError as ve:
                                    print(f"*-*-*-*-*-*-*-*-*-*-*-*-*-*-* Error updating product {request.json[data_field]} with error {ve}")
                                    raise ve
                            else:
                                setattr(product_to_update, data_field, request.json[data_field])
                        #else:
                        #    print(f"*-*-*-*-*-*-*-*-*-*-*-*-*-*-* {data_field} skipped")

                    sdb.session.commit()

                    return jsonify({"message": "Product updated successfully"}),200
                else:
                    return jsonify({"error": "Product not found"}),400
            except ValueError as ve:
                sdb.session.rollback()
                print("ValueError updating product: ", ve)
                return jsonify({"error": "Failed to update product",
                                "message": str(ve)}),400 
            except Exception as e:
                sdb.session.rollback()                
                print("Error updating product: (outside exception)", e)
                return jsonify({"error": "Failed to update product",
                                "message": str(e)}),500
            
            finally:
                sdb.session.close()
        elif request.method == 'POST':
            #create a new product record
            try:               
                product_to_add = SamuraiProducts()

                if 'product' in request.json and request.json['product'] is not None:
                    product_to_add.product = request.json['product']
                    #product is required, if it exists and is not empty proceed with the rest else throw and error
                    data_fields = ['capital', 'expOther', 'expSaas', 'expMaint', 'current', 'deviceType', 'vendor',
                                   'productAlias', 'modelNumber', 'maint1PartNumber', 'maint1Description', 'maint2PartNumber',
                                   'maint2Description', 'productType', 'announcement', 'productLink', 'productNotes',
                                   'end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 
                                   'end_of_support']
                    date_fields = ['end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 'end_of_support']
                    for data_field in data_fields:
                        if data_field in request.json and request.json[data_field] is not None and request.json[data_field] != "":
                            if data_field in date_fields:
                                #validate the given dates are in the right format, if not throw and error
                                try:
                                    datetime.datetime.strptime(request.json[data_field], '%Y-%m-%d')
                                    setattr(product_to_add, data_field, request.json[data_field])
                                except ValueError as ve:
                                    print(f"*-*-*-*-*-*-*-*-*-*-*-*-*-*-* Error updating product {request.json[data_field]} with error {ve}")
                                    raise ve
                            else:
                                setattr(product_to_add, data_field, request.json[data_field])

                    #Since this will always be a "custom" product we need to set the discovered attribute to 1
                    product_to_add.discovered = 1

                    sdb.session.add(product_to_add)
                    sdb.session.commit()

                    return jsonify({"message": "Product created successfully"}), 201
                else:
                    return jsonify({"error": "Failed to add a new product",
                                    "message": "Product name is a required field"}), 409
            except ValueError as ve:
                sdb.session.rollback()
                print("ValueError updating product: ", ve)
                return jsonify({"error": "Failed to update product",
                                "message": str(ve)}),400 
            except Exception as e:
                sdb.session.rollback()
                print("Error adding a new product", str(e))
                return jsonify({"error": "Failed to add a new product"}), 500
            finally:
                sdb.session.close()

        elif request.method == 'DELETE':
            try:
                #need to search through samurai_replacement.productNew for for ID - fail delete if any found
                replacement_in_use = sdb.session.query(SamuraiReplacements).filter_by(productNew=id).all()
                #need to search through samurai_master.newModel for ID - fail delete if any found
                override_in_use = sdb.session.query(SamuraiMaster).filter_by(newModel=id).all()
                if not replacement_in_use and not override_in_use:
                    product_to_delete = sdb.session.query(SamuraiProducts).filter_by(id=id).first()
                    
                    if product_to_delete:
                        sdb.session.delete(product_to_delete)
                        sdb.session.commit()

                        return jsonify({"message": "Product removal successful"}), 200
                    else:
                        return jsonify({"error": "Failed to remove requested product",
                                        "message": "Requested product id could not be found"}), 400
                else:
                    replacement_output_list = []
                    if replacement_in_use:
                        for row in replacement_in_use:
                            output = {}
                            product = sdb.session.query(SamuraiProducts).filter_by(id=row.productOld).first()
                            output['product_name'] = product.productAlias
                            replacement_output_list.append(output)
                    override_output_list = []
                    if override_in_use:
                        for row in override_in_use:
                            override_output_list.append({"device_name": row.name})

                    return jsonify({"error": "Failed to remove requested product",
                                    "message": "Requested product is still in use",
                                    "product_replacement_usage": replacement_output_list,
                                    "samurai_override_usage": override_output_list}), 409
            except Exception as e:
                sdb.session.rollback()
                print("Error removing procut", str(e))
                return jsonify({"error": "Failed to remove requested product",
                                "message": str(e)}), 500
            finally:
                sdb.session.close()
    elif task == "mergeData":
        #Merge a custom product into a discovered product
        #id is the id of the discovered product
        #payload contains all of the information (including id) from the custom product.
        if request.method == 'PUT':
            try:
                source_product_id = request.json['id']
                dest_product_id = id

                if source_product_id == dest_product_id:
                    return jsonify({"message": "Data validation error",
                                    "error": "Source and Destinatino products cannot be the same product"}), 500                    

                with sdb.session.begin():
                    try:
                        dest_product = sdb.session.query(SamuraiProducts).filter_by(id=dest_product_id).first()
                        source_product = sdb.session.query(SamuraiProducts).filter_by(id=source_product_id).first()

                    except Exception as e:
                        raise Exception("Error retrieving source or destination product from the db: ", str(e))
                    
                    #Validate both the source and destination products exist and are of the right type
                    if not dest_product or dest_product.discovered != 0:
                        return jsonify({"message": "Data validation error",
                                        "error": "Destination product not found or it is not a discovered product"}), 500
                        
                    if not source_product or source_product.discovered != 1:
                        return jsonify({"message": "Data validation error",
                                        "error": "Source product not found or it is not a custom product"}), 500

                    # Merge Data Section             
                    try:
                        #overwrite all of dest_product's fields with the source product's data from payload
                        #'id', 'product', 'productAlias', 'discovered' should not be overwritten even though they may be in the payload
                        data_fields = ['capital', 'expOther', 'expSaas', 'expMaint', 'current', 'deviceType', 'vendor',
                                       'modelNumber', 'maint1PartNumber', 'maint1Description', 'maint2PartNumber',
                                       'maint2Description', 'productType', 'announcement', 'productLink', 'productNotes',
                                       'end_of_sale', 'end_of_hw_renew', 'end_of_sw_sec_upd', 'end_of_hw_support', 'end_of_support']
                        for data_field in data_fields:
                            if data_field in request.json and request.json[data_field] is not None:
                                setattr(dest_product, data_field, request.json[data_field])

                    except Exception as e:
                        raise Exception("Error merging custom product data: ", str(e))

                    # Replace Source Product Usage with Dest Product Section
                    try:
                        #need to search through samurai_replacement.productNew for for ID - replace with dest_product_id
                        replacement_in_use = sdb.session.query(SamuraiReplacements).filter_by(productNew=source_product_id).all()
                        
                        #Loop through all of the items found and replace with dest_product_id
                        if replacement_in_use:
                            for row in replacement_in_use:
                                row.productNew = dest_product_id
                    except Exception as e:
                        raise Exception("Error discovering merge source replacement usage: ", str(e))
                    
                    try:
                        #need to search through samurai_master.newModel for ID - replace with dest_product_id
                        override_in_use = sdb.session.query(SamuraiMaster).filter_by(newModel=source_product_id).all()
                        
                        #Loop through all of the items found and resplace with dest_product_id
                        if override_in_use:
                            for row in override_in_use:
                                row.newModel = dest_product_id
                    except Exception as e:
                        raise Exception("Error discovering merge source override usage: ", str(e))

                    # Delete Source Product Section
                    try:
                        sdb.session.delete(source_product)
                    
                    except Exception as e:
                        raise Exception("Error deleting merge source: ", str(e))

                    #if everything was successful commit it to the db
                    try:
                        sdb.session.commit()
                    except Exception as e:
                        raise Exception("Error committing the changes: ", str(e))

                return jsonify({"message": "Request for merge processed successfully"}),200
        
            except Exception as e:
                #rollback the whole thing if there was an error anywhere
                sdb.session.rollback()
                print("Unexpected error: ", str(e))
                return jsonify({"message": "Unexpected error occurred",
                                "error": str(e)}),500
            finally:
                sdb.session.close()

@app.route("/samurai/product_replacement/<task>", methods=['GET'])
@app.route("/samurai/product_replacement/<task>/<id>", methods=['PUT', 'POST', 'DELETE'])
@login_required
def samurai_load_product_replacement(task="", id=""):
    """
        Returns a list of dictionaries formatted like this:
        {
        "id": 1409,
        "productNew": 1548,
        "productNewName": "PA-VM",
        "productOld": 1548,
        "productOldName": "PA-VM"
        },
    """
    if task == "getData":
        try:
            output_list = []

            # Alias the samurai_products table since we are using it twice
            sp1 = aliased(SamuraiProducts)
            sp2 = aliased(SamuraiProducts)

            replacement_data = (
                sdb.session.query(
                    SamuraiReplacements,
                    sp1.product.label('ProductOldName'),
                    sp2.product.label('ProductNewName')
                ) 
                .join(sp1, SamuraiReplacements.productOld == sp1.id) 
                .join(sp2, SamuraiReplacements.productNew == sp2.id) 
                .all()
            )

            for samurai_replacements, productOldName, productNewName, in replacement_data:
                row_dict = {}
                row_dict['id'] = samurai_replacements.id
                row_dict['productOld'] = samurai_replacements.productOld
                row_dict['productNew'] = samurai_replacements.productNew
                row_dict['productOldName'] = productOldName
                row_dict['productNewName'] = productNewName
                output_list.append(row_dict)

            return jsonify(output_list), 200

        except Exception as e:
            print("*******************Error retreiving data", e)
            return jsonify({"error": "Failed to retrieve product replacement data",
                            "message": str(e)}), 500
    
    elif task == "updateData":
        if request.method == 'PUT':
            try:
                product_to_update = sdb.session.query(SamuraiReplacements).filter_by(id=id).first()
                
                if product_to_update:
                    if 'productNew' in request.json and request.json['productNew'] is not None:
                        product_to_update.productNew = request.json['productNew']
                    if 'productOld' in request.json and request.json['productOld'] is not None:
                        product_to_update.productOld = request.json['productOld']

                    sdb.session.commit()

                    return jsonify({"message": "Product updated successfully"}),200
                
                else:
                    return jsonify({"error": "Product not found"}),400
                
            except Exception as e:
                print("Error updating product replacement: ", e)
                return jsonify({"error": "Failed to update product replacement",
                                "message": str(e)}),500
            
            finally:
                sdb.session.close()

        elif request.method == 'POST':
            return jsonify({"error": "Method not defined"})
        elif request.method == 'DELETE':
            return jsonify({"error": "Method not defined"})

@app.route("/gmi-latency")
def latency():
	return render_template('latency.html', auth=get_auth())

@app.route("/rest/v1/chinasmsgateway", methods=['GET', 'POST'])
def ChinaSMSGateway():
    if request.method == 'GET':
        print("*****************")
        print("*****SMS*GET*****")
        print("*****************")
        return {"message": "This is a GET request for the ChinaSMSGateway"}, 200
    if request.method == 'POST':
        #sort = request.args.get('sort', "asc", type=str)
        #request.json["from_payload"]
        print("*****************")
        print("***SMS*POST******")
        print("*****************")
        if request.json:
            print("payload", request.json)
            payload = request.json
        else:
            payload = "No payload found"
        if request.args:
            print("URL Arguments", request.args)
            args = request.args
        else:
            args = "No URL Arguments found"
        return {
                "message": "This is a POST request for the ChinaSMSGateway",
                "payload": payload,
                "url_args": args
               }, 200

@app.route("/")
@app.route('/<task>')
@login_required
def application(task=""):
    location =  request.args.get('Location')
    return render_template('control.html', auth=get_auth(), task=task, location=location)

@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

@app.after_request
def refresh_expiring_jwts(response):
    token = session.get('token', None)
    if token:
        try:
            token_payloads = jwt.decode(session['token'], app.secret_key, algorithms=["HS256"])
            exp_timestamp = token_payloads.get('exp')
            syslog.debug("Token is being refreshed")
            if sys.version_info[0] > 2:
                target_timestamp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
                exp_timestamp = datetime.datetime.fromtimestamp(exp_timestamp, tz=datetime.timezone.utc)
            else:
                target_timestamp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            if target_timestamp > exp_timestamp:
                if sys.version_info[0] > 2:
                    token_payloads["exp"] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
                else:
                    token_payloads["exp"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                access_token = jwt.encode(token_payloads,app.secret_key,algorithm='HS256')
                session["token"] = access_token
        except Exception as e:
            print("Error occured for refresh token due to {}".format(e))
    return response
        

if __name__ == "__main__":
    app.run(debug=True)

