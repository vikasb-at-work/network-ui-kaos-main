from base_orm_model import *


class PortAccessRoleGatewayZone(Base):
    __tablename__ = 'port_access_role_gateway_zone'
    id = Column(Integer, primary_key=True)
    zone_name = Column(String(128), nullable=False, unique=True, default="")
    zone_description = Column(String(255), default="")
    zone_number = Column(Integer, default=0) 

class PortAccessRoleGatewayZoneSchema(base_ma.Schema):
    class Meta:
        fields = (
                    'id',
                    'zone_name',
                    'zone_description',
                    'zone_number'
        )
