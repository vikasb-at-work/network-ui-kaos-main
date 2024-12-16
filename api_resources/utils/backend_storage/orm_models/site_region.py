

from sqlalchemy import Column, Integer, String, Boolean, DateTime, func, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class SiteRegion(Base):
    __tablename__ = 'cp_region'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), nullable=False)
    desc = Column(String(256))
    cpProfile = relationship("SiteCPProfile", back_populates="siteRegion")

