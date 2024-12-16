from base_orm_model import *


class SwitchDS(Base):
    __tablename__ = 'dyn_seg'
    id = Column(Integer, primary_key=True)
    user_email = Column(String(200), nullable=False)
    switch_name = Column(String(50), nullable=True, default=None)
    site_name = Column(String(50), nullable=False)
    model = Column(String(50), nullable=False)
    mgmt_ip = Column(String(25), nullable=False)
    controller = Column(Boolean, nullable=False)
    oobm = Column(Boolean, nullable=False)
    base_config = Column(Boolean, nullable=False)
    add_to_clearpass = Column(Boolean, nullable=False)
    data_ip = Column(String(25), nullable=True)
    admin_vlan = Column(Integer, nullable=True)
    voice_vlan = Column(Integer, nullable=True)
    p_controller_ip = Column(String(16), nullable=True)
    s_controller_ip = Column(String(16), nullable=True)
    sourced_vlan = Column(Integer, nullable=True, default=None)
    date_time = Column(DateTime, default=func.now())
    status = Column(String(20), default="NOT DONE")
    primary_clearpass_ip = Column(String(25), nullable=True)
    secondary_clearpass_ip = Column(String(25), nullable=True)
    switch_type = Column(String(20), nullable=True)
    auto_vlan_detection = Column(Boolean, nullable=False)
    rfmgmt_vlan = Column(Integer, nullable=True)
    gmiwli_vlan = Column(Integer, nullable=True)
    wpa_ewn_vlan = Column(Integer, nullable=True)
    rf_guest_vlan = Column(Integer, nullable=True)


class SwitchDSSchema(base_ma.Schema):
    class Meta:
        fields = ('id',
                  'user_email',
                  'switch_name',
                  'site_name',
                  'model',
                  'mgmt_ip',
                  'controller',
                  'oobm',
                  'base_config',
                  'add_to_clearpass',
                  'data_ip',
                  'admin_vlan',
                  'voice_vlan',
                  'p_controller_ip',
                  's_controller_ip',
                  'sourced_vlan',
                  'date_time',
                  'status',
                  'primary_clearpass_ip',
                  'secondary_clearpass_ip',
                  'switch_type',
                  'auto_vlan_detection',
                  'rfmgmt_vlan',
                  'gmiwli_vlan',
                  'wpa_ewn_vlan',
                  'rf_guest_vlan')
