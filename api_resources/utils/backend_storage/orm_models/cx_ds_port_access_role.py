from base_orm_model import *
import sys
if sys.version_info[0] > 2:
    from network_iac_common_utils.switchFunctionHelper import vlans_to_bytes, vlans_from_list,\
        vlans_from_bytes, vlans_to_list
else:
    sys.path.insert(1, '/var/www/control/Helpers')
    from switchFunctionHelper import vlans_from_list, vlans_to_bytes, vlans_from_bytes, vlans_to_list


class CXDSPortAccessRole(Base):

    """
    Author: Brian - working on this
    Documentation link: https://www.arubanetworks.com/techdocs
    /AOS-CX/10.12/HTML/security_6200-6300-6400/Content/Chp_Port_acc
    /Port_acc_rol_cmds/por-acc-rol-cmd-fl-10.htm
    Dan used 0 or False or "" for "not exist"
    """
    __tablename__ = 'switch_port_access_roles'

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True, default="")
    associate_policy = Column(String(64), default="")
    gateway_zone = Column(Integer, default=0)
    auth_mode = Column(String(12), default="")
    cached_reauth_period = Column(BigInteger, default=None)
    client_inactivity = Column(BigInteger, default=None)
    description = Column(String(255), default="")
    device_traffic_class = Column(String(32), default="")
    mtu = Column(Integer, default=None)
    poe_priority = Column(String(32), default="")
    private_vlan = Column(String(32), default="")
    reauth_period = Column(BigInteger, default=0)
    session_timeout = Column(BigInteger, default=0)
    stp_admin_edge_port = Column(Boolean, default=False)
    trust_mode = Column(String(32), default="")
    vlan_access_id = Column(String(64), default="")
    vlan_access_name = Column(String(32), default="")
    vlan_trunk_allowed_id = Column(LargeBinary(512), default=vlans_to_bytes(vlans_from_list()))
    vlan_trunk_allowed_name = Column(String(1750), default="")
    vlan_trunk_native_id = Column(String(64), default="")
    vlan_trunk_native_name = Column(String(32), default="")
    associate_captive_portal_profile = Column(String(64), default="")
    associate_macsec_policy = Column(String(64), default="")
    gateway_role = Column(String(128), default="")


class CXDSPortAccessRoleSchema(base_ma.Schema):

    class Meta:
        model = CXDSPortAccessRole
        fields = ('id',
                  'name',
                  'associate_policy',
                  'gateway_zone',
                  'auth_mode',
                  'cached_reauth_period',
                  'client_inactivity',
                  'description',
                  'device_traffic_class',
                  'mtu',
                  'poe_priority',
                  'private_vlan',
                  'reauth_period',
                  'session_timeout',
                  'stp_admin_edge_port',
                  'trust_mode',
                  'vlan_access_id',
                  'vlan_access_name',
                  'vlan_trunk_allowed_id',
                  'vlan_trunk_allowed_name',
                  'vlan_trunk_native_id',
                  'vlan_trunk_native_name',
                  'associate_captive_portal_profile',
                  'associate_macsec_policy',
                  'gateway_role'
                  )

    def dump(self, obj, *args, **kwargs):
        if isinstance(obj, list):
            for item in obj:
                self._vlan_list_formatting(item)
        else:
            self._vlan_list_formatting(obj)
        return super(CXDSPortAccessRoleSchema, self).dump(obj, *args, **kwargs)

    def _vlan_list_formatting(self, obj):
        for field in self.Meta.fields:
            if field == 'vlan_trunk_allowed_id':
                value = self._get_field_value(obj, field)
                new_list = vlans_to_list(vlans_from_bytes(value))
                self._set_field_value(obj, field, new_list)

    def _get_field_value(self, obj, field):
        return getattr(obj, field, 0) if not isinstance(obj, dict) else obj.get(field)

    def _set_field_value(self, obj, field, value):
        if isinstance(obj, dict):
            obj[field] = value
        else:
            setattr(obj, field, value)


class TestSwaggerTable(Base):
    __tablename__ = 'test_swagger_table_creation'

    id = Column(Integer, primary_key=True)
    name_test = Column(String(128), nullable=False, unique=True, default="")
