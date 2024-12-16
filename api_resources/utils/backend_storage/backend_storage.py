from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker
import sys

if sys.version_info[0] > 2:
    from api_resources.api_constants.constants import *
else:
    from api_resources.api_constants.constants import *


class SQLBackendStorage:
    def __init__(self, db_url):
        try:
            self.engine = create_engine(db_url, echo=True)
            self.engine.connect()
            self.Session = sessionmaker(bind=self.engine)
        except Exception as e:
            raise Exception("Error occured: "+str(e))

    def insert(self, obj):
        try:
            session = self.Session()
            session.add(obj)
            session.commit()
            session.close()
        except Exception as e:
            raise Exception("Error occured: "+str(e))

    def select_by_id(self, model_class, id):
        session = self.Session()
        obj = session.query(model_class).filter_by(id=id).first()
        session.close()
        return obj
        
    def select_all(self, model_class, child_class=None):
        session = self.Session()
        if not child_class:
            obj = session.query(model_class).all()
        else:
            obj = session.query(model_class).join(child_class).all()
        session.close()
        return obj 

    def select_all_with_filter(self, model_class, **filters):
        session = self.Session()
        query = session.query(model_class)
        for k,v in filters.items():
            query = query.filter(getattr(model_class, k) == v)
        objects = query.all()
        session.close()
        return objects

    def update(self, model_class, data, id):
        session = self.Session()
        query = session.query(model_class)
        try:
            query = query.filter(getattr(model_class, "id") == id)
            query.update(data)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def delete(self, model_class, id):
        session = self.Session()
        try:
            session.query(model_class).filter(getattr(model_class, "id") == id).delete()
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
