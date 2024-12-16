from sqlalchemy import Column, Integer, String, Boolean,\
    DateTime, func, ForeignKey, Index, SmallInteger, Float, BigInteger, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from flask_marshmallow import Marshmallow
import re


Base = declarative_base()
base_ma = Marshmallow()
