from base_orm_model import *


class SiteRegion(Base):
    __tablename__ = 'cp_region'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), nullable=False)
    desc = Column(String(256))
    api_url = Column(String(128))
    cluster_url = Column(String(128))
    auth_profile = Column(String(128))
    go_url = Column(String(128))
    cp_profile_region = relationship("SiteCPProfile", back_populates="region_data")
    gmi_site_region = relationship("GMISites", back_populates="region_data")


class SiteRegionSchema(base_ma.Schema):
    class Meta:
        fields = ('id',
                  'name',
                  'desc',
                  'api_url',
                  'cluster_url',
                  'auth_profile',
                  'go_url')


class SiteCPProfile(Base):
    __tablename__ = 'cp_site_profile'
    id = Column(Integer, primary_key=True)
    site = Column(String(32), index=True, nullable=False, unique=True)
    region = Column(Integer, ForeignKey("cp_region.id"), nullable=False, default=1)
    primary_ip = Column(String(64))
    secondary_ip = Column(String(64))
    cp_url = Column(String(128))
    controller1_ip = Column(String(64))
    controller2_ip = Column(String(64))
    record_type = Column(SmallInteger, default=1)
    __table_args__ = (Index('cp_region_site_index', "region", "site", "record_type", unique=True),)
    region_data = relationship("SiteRegion", foreign_keys='SiteCPProfile.region', lazy='joined')


class SiteCPProfileSchema(base_ma.Schema):
    class Meta:
        model = SiteCPProfile
        fields = ('id', 'site', 'region', 'primary_ip',
                  'secondary_ip', 'cp_url', 'controller1_ip',
                  'controller2_ip', 'record_type', 'region_data')
    region_data = base_ma.Nested(SiteRegionSchema)


class GMISites(Base):
    __tablename__ = 'gmi_sites'
    id = Column(Integer, primary_key=True)
    site = Column(String(24), nullable=False, index=True, unique=True)
    equipment = Column(String(8), nullable=False, default='0')
    type = Column(String(32), nullable=False)
    city = Column(String(64), nullable=False)
    state = Column(String(64), nullable=False)
    country = Column(String(64), nullable=False)
    address = Column(String(256))
    nickname = Column(String(256), nullable=False)
    region = Column(Integer, ForeignKey("cp_region.id"), nullable=False,
                    default=1)
    site_override = Column(String(24), nullable=True)
    lat = Column(Float, nullable=True)
    lng = Column(Float, nullable=True)
    postal_code = Column(String(16), nullable=True)
    aruba_central_id = Column(Integer, nullable=True)
    address2 = Column(String(256), nullable=True)
    address3 = Column(String(256), nullable=True)
    attention = Column(String(256), nullable=True)
    suffix = Column(String(256), nullable=True)
    region_data = relationship("SiteRegion", foreign_keys="GMISites.region", lazy='joined')


class GMISiteSchema(base_ma.Schema):
    class Meta:
        model = GMISites
        fields = ('id', 'site', 'equipment', 'type', 'city', 'state', 'country',
                  'address', 'nickname', 'region', 'site_override',
                  'lat', 'lng', 'postal_code', 'aruba_central_id', 'address2',
                  'address3', 'attention', 'suffix',
                  'region_data')
    region_data = base_ma.Nested(SiteRegionSchema)

    def dump(self, obj, *args, **kwargs):
        self._clean_non_ascii(obj)
        try:
            return super(GMISiteSchema, self).dump(obj, *args, **kwargs)
        except UnicodeDecodeError:
            if isinstance(obj, list):
                for item in obj:
                    self._encode_strings(item)
            else:
                self._encode_strings(obj)
            return super(GMISiteSchema, self).dump(obj, *args, **kwargs)

    def _encode_strings(self, obj):
        for field in self.Meta.fields:
            value = self._get_field_value(obj, field)
            if isinstance(value, str):
                encoded_data = value.encode('utf-8', 'ignore').decode('utf-8')
                self._set_field_value(obj, field, encoded_data)

    def _clean_strings(self, obj):
        for field in self.Meta.fields:
            value = self._get_field_value(obj, field)
            if isinstance(value, str):
                cleaned_value = re.sub(r'[^\x00-\x7F]', '', value)
                self._set_field_value(obj, field, cleaned_value)

    def _clean_non_ascii(self, obj):
        if isinstance(obj, list):
            for item in obj:
                self._clean_strings(item)
        else:
            self._clean_strings(obj)

    def _get_field_value(self, obj, field):
        return getattr(obj, field, None) if not isinstance(obj, dict) else obj.get(field)

    def _set_field_value(self, obj, field, value):
        if isinstance(obj, dict):
            obj[field] = value
        else:
            setattr(obj, field, value)

      
