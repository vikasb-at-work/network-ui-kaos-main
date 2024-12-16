from base_orm_model import *


class GMICore(Base):
    __tablename__ = 'sla_locations'
    id = Column(Integer, primary_key=True)
    core = Column(String(64))
    description = Column(String(128))
    asNum = Column(Integer)


class GMICoreSchema(base_ma.Schema):
    class Meta:
        fields = ('id', 'core', 'description', 'asNum')
