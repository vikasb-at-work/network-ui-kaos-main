from base_orm_model import *


class PolicyQOS(Base):
    __tablename__ = 'switch_qos_policy'
    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False, default="", unique=True)
    cos = Column(Integer, default=0)
    apply_policy_name = Column(String(128), default="")
    trust = Column(Integer, default=0)
    set_dscp = Column(Integer, default=0)
    rate_limit_type = Column(Integer, default=0)
    rate_limit_subtype = Column(Integer, default=0)
    rate_limit_value = Column(Integer, default=0)
    rate_limit_value_type = Column(Boolean, default=False)
    qos_shape = Column(Integer, default=0)


class PolicyQOSSchema(base_ma.Schema):
    class Meta:
        fields = ('id', 'name', 'cos', 'apply_policy_name', 'trust', 'set_dscp',
                  'rate_limit_type', 'rate_limit_subtype', 'rate_limit_value',
                  'rate_limit_value_type', 'qos_shape')
