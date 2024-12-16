from base_orm_model import *


class SwitchPortRoleProfile(Base):
    __tablename__ = 'switch_port_role_profile'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True, default="")
    portaccess_ps = Column(Boolean, default=False)
    portaccess_ps_mac = Column(String(32), default="")
    portfilter = Column(String(128), default="")
    portaccess_fb_role = Column(String(256), default="")
    aaa_auth_precedence = Column(Integer, default=0) 
    portaccess_ob_precedence = Column(Integer, default=0) 
    portaccess_ob_method = Column(Integer, default=0) 
    aaa_auth_priority = Column(Integer, default=0) 
    portaccess_security_violation = Column(Integer, default=0) 
    portaccess_security_violation_timer = Column(Integer, default=0) 
    portaccess_security_violation_recovery = Column(Integer, default=0) 
    critical_role = Column(String(128), default="")
    critical_voice_role = Column(String(128), default="")
    preauth_role = Column(String(128), default="")
    reject_role = Column(String(128), default="")
    auth_role = Column(String(128), default="")
    auth_mode = Column(Integer, default=0) 
    allow_lldp_bpdu = Column(Boolean, default=False)
    allow_cdp_bpdu = Column(Boolean, default=False)
    allow_lldp_auth = Column(Boolean, default=False)
    allow_cdp_auth = Column(Boolean, default=False)
    radius_override = Column(Integer, default=0) 
    allow_flood_traffic = Column(Integer, default=0) 
    aaa_auth_mac = Column(Integer, default=0) 
    aaa_auth_mac_cached_reauth = Column(Boolean, default=False)
    aaa_auth_dot1x = Column(Integer, default=0) 
    portaccess_device_profile = Column(Boolean, default=False)
    portaccess_device_profile_mode = Column(Integer, default=0) 
    portaccess_ps_client_limit = Column(Integer, default=0) 
    aaa_auth_client_limit = Column(Integer, default=0) 
    aaa_auth_client_limit_multi = Column(Integer, default=0) 
    aaa_auth_mac_quiet = Column(Integer, default=0) 
    aaa_auth_mac_reauth = Column(BigInteger, default=0) 
    aaa_auth_mac_reauth_period = Column(BigInteger, default=0) 
    aaa_auth_dot1x_quiet = Column(Integer, default=0) 
    aaa_auth_dot1x_cached_reauth = Column(BigInteger, default=0) 
    aaa_auth_dot1x_max_retries = Column(Integer, default=0) 
    aaa_auth_dot1x_reauth_period = Column(BigInteger, default=0) 
    aaa_auth_dot1x_discovery_period = Column(Integer, default=0) 
    aaa_auth_dot1x_max_eapol = Column(Integer, default=0) 
    aaa_auth_dot1x_eapol_timeout = Column(Integer, default=0) 
    aaa_auth_dot1x_initial_response_timeout = Column(Integer, default=0)
    description = Column(String(255), default="")


class SwitchPortRoleProfileSchema(base_ma.Schema):
    class Meta:
        fields = (
                    'id',
                    'name',
                    'portaccess_ps',
                    'portaccess_ps_mac',
                    'portfilter',
                    'portaccess_fb_role',
                    'aaa_auth_precedence',
                    'portaccess_ob_precedence',
                    'portaccess_ob_method',
                    'aaa_auth_priority',
                    'portaccess_security_violation',
                    'portaccess_security_violation_timer',
                    'portaccess_security_violation_recovery',
                    'critical_role',
                    'critical_voice_role',
                    'preauth_role',
                    'reject_role',
                    'auth_role',
                    'auth_mode',
                    'allow_lldp_bpdu',
                    'allow_cdp_bpdu',
                    'allow_lldp_auth',
                    'allow_cdp_auth',
                    'radius_override',
                    'allow_flood_traffic',
                    'aaa_auth_mac',
                    'aaa_auth_mac_cached_reauth',
                    'aaa_auth_dot1x',
                    'portaccess_device_profile',
                    'portaccess_device_profile_mode',
                    'portaccess_ps_client_limit',
                    'aaa_auth_client_limit',
                    'aaa_auth_client_limit_multi',
                    'aaa_auth_mac_quiet',
                    'aaa_auth_mac_reauth',
                    'aaa_auth_mac_reauth_period',
                    'aaa_auth_dot1x_quiet',
                    'aaa_auth_dot1x_cached_reauth',
                    'aaa_auth_dot1x_max_retries',
                    'aaa_auth_dot1x_reauth_period',
                    'aaa_auth_dot1x_discovery_period',
                    'aaa_auth_dot1x_max_eapol',
                    'aaa_auth_dot1x_eapol_timeout',
                    'aaa_auth_dot1x_initial_response_timeout',
                    'description'
        )
