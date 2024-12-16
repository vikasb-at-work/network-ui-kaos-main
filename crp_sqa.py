from sqlalchemy import create_engine, Column, String, Integer, Float, Date, func, and_, desc, asc
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import date, datetime
from marshmallow import Schema, fields
import sys
if sys.version_info[0] > 2:
    from network_iac_common_utils.sys_environment import environment
else:
    sys.path.insert(1, '/var/www/control/Helpers')
    from sys_environment import environment 
# from sys_environment import environment
#from authHelper import Auth
from pprint import pprint

#pull in the db environment based on the 'PLATFORM' environment variable
env = environment()

#AUTH PROFILE NAMES
DB_KEY = env.DB_Auth_Profile

#GET AUTH
#myAuth = Auth(profile = [DB_KEY])

def grabPass(file="/etc/network/data/mid_password_file.txt",profile="root"):
    profiles = open(file, "r")
    rval = None
    for item in profiles:
        [user, pw] = item[:-1].split(":")
        if user == profile:
            rval = pw
            break
    profiles.close()
    return (rval)

dbpw = grabPass("/etc/network/data/mid_password_file.txt","dan")

if sys.version_info[0] > 2:
    db_connection = "mysql+pymysql://{}:{}@{}/kaosdb".format("dan",dbpw, env.DB)
else:
    db_connection = "mysql://{}:{}@{}/kaosdb".format("dan", dbpw, env.DB)

engine = create_engine(db_connection)
session = sessionmaker(bind=engine)
db_session = session()

Base = declarative_base()

class CradlepointStats(Base):
    __tablename__ = 'cradlepoint_stats'

    id = Column(Integer, primary_key=True, autoincrement=True)
    Cradlepoint = Column(String(255), default="", nullable=False)
    MB_used = Column(Float, default=0.0, nullable=False)
    date = Column(Date, default=datetime.now().date(), nullable=False)

class CradlepointStatsSchema(Schema):
    id = fields.Int(dump_only=True)
    Cradlepoint = fields.Str()
    MB_used = fields.Float()
    date = fields.Date()
    Total_MB_Used = fields.Float()

def SQAGetDataUsageSpecificCPSpecificDate(cradlepoint, query_date):
    """
    returns a list of one dictionary
    [{'Cradlepoint': 'BVA-CP2',
      'MB_used': 820.8515958786011,
      'date': '2023-07-14',
      'id': 52851}]
    """
    query_date = datetime.strptime(query_date, '%Y-%m-%d')
    #print(f'query_date = {query_date}')
    target_date = query_date.strftime('%Y-%m-%d')  # Replace with your desired date
    #print(f'target_date = {target_date}')
    stats = db_session.query(CradlepointStats).filter(CradlepointStats.date == target_date,
                                                      CradlepointStats.Cradlepoint == cradlepoint).one()
    stats_schema = CradlepointStatsSchema(many=True)
    stats_data = stats_schema.dump(stats)
    if sys.version_info[0] > 2:
        return stats_data
    else:
        return stats_data[0]

def SQAGetDataUsageSpecificCPAll(cradlepoint):
    """
    returns a list of multiple dictionaries
    [{'Cradlepoint': 'BVA-CP2',
      'MB_used': 872.5520038604736,
      'date': '2023-08-15',
      'id': 57327},
     {'Cradlepoint': 'BVA-CP2',
      'MB_used': 1034.472604751587,
      'date': '2023-08-10',
      'id': 56817}]
    """
    all_usage = db_session.query(CradlepointStats).filter(CradlepointStats.Cradlepoint == cradlepoint).order_by(CradlepointStats.date.desc()).limit(50).all()
    stats_schema = CradlepointStatsSchema(many=True)
    all_usage_data = stats_schema.dump(all_usage)
    if sys.version_info[0] > 2:
        return all_usage_data
    else:
        return all_usage_data[0]

def SQAListAllObjects():
    #List Devices (and fills the device dropdowns)
    #Returns a list of strings containing the names of all Cradlepoints in the database
    all_cradlepoints = db_session.query(CradlepointStats.Cradlepoint).distinct().order_by(CradlepointStats.Cradlepoint.asc()).all()
    stats_schema = CradlepointStatsSchema(many=True)
    #Returns a list of dictionaries each containing [{"Cradlepoint": "CP-NAME1"}, {"Cradlepoint": "CP-NAME2"}]
    cp_list_of_dicts = stats_schema.dump(all_cradlepoints)
    #This peels out each "CP-NAME" in the list of dictionaries so we end up with a simple list of names
    if sys.version_info[0] > 2:
        cp_list = [d["Cradlepoint"] for d in cp_list_of_dicts]
    else:
        cp_list = [d["Cradlepoint"] for d in cp_list_of_dicts[0]]
    return cp_list


def SQAFindTopXDeviceUsage(top_x=10):
    #Top 20 All time usage
    #Find and return top x highest all time usage
    query = (
        db_session.query(CradlepointStats.Cradlepoint, func.sum(CradlepointStats.MB_used).label('Total_MB_Used'))
        .group_by(CradlepointStats.Cradlepoint)
        .order_by(func.sum(CradlepointStats.MB_used).desc())
        .limit(top_x)
    )
    top_x_usage = query.all()

    stats_schema = CradlepointStatsSchema(many=True)
    max_usage_top_x = stats_schema.dump(top_x_usage)
    if sys.version_info[0] > 2:
        return max_usage_top_x
    else:
        return max_usage_top_x[0]

def SQAFindTopXHighestDays(top_x=10):
    #Top 20 Highest single day usage
    #query = 'SELECT Cradlepoint, MB_used, date FROM cradlepoint_stats ORDER BY MB_used DESC LIMIT {}'.format(top_x)
    query = (
        db_session.query(CradlepointStats.Cradlepoint, CradlepointStats.MB_used, CradlepointStats.date)
        .order_by(CradlepointStats.MB_used.desc())
        .limit(top_x)
    )
    top_x_usage = query.all()
    stats_schema = CradlepointStatsSchema(many=True)
    max_usage_top_x = stats_schema.dump(top_x_usage)
    if sys.version_info[0] > 2:
        return max_usage_top_x
    else:
        return max_usage_top_x[0]

def SQATotalDays():
    #Returns the total number of unique days in the database
    """('SELECT COUNT(DISTINCT date) AS total_days from cradlepoint_stats').fetchone()"""
    total_days = db_session.query(func.count(func.distinct(CradlepointStats.date)).label('date')).scalar()
    #print(f'total_days = {total_days}')
    return total_days

def WebSQASystemDailyUsage():
    #System Wide Daily Usage
    #Returns a list of dictionaries containg the total system usage for each day
    """('SELECT date, SUM(MB_used) AS total_mb_used FROM cradlepoint_stats GROUP BY date ORDER BY date DESC;').fetchall()"""
    system_daily_usage = (
        db_session.query(CradlepointStats.date, func.sum(CradlepointStats.MB_used).label('MB_used'))
        .group_by(CradlepointStats.date)
        .order_by(CradlepointStats.date.desc())
        .all()
    )
    stats_schema = CradlepointStatsSchema(many=True)
    sys_usage = stats_schema.dump(system_daily_usage)
    #print(sys_usage[0])
    if sys.version_info[0] > 2:
        return sys_usage
    else:
        return sys_usage[0]

def WebSQALastXTotalUsage(day_limit= 0):
    lastX_days = (
        db_session.query(CradlepointStats.date, func.sum(CradlepointStats.MB_used))
        .group_by(CradlepointStats.date)
        .order_by(CradlepointStats.date.desc())
        .limit(day_limit)
        .all()
    )
    lastX_total_usage = 0
    for row in lastX_days:
        lastX_total_usage += row[1]
    return lastX_total_usage

def WebSQAAllTimeSystemDataUsage():
    """('SELECT SUM(MB_used) FROM cradlepoint_stats').fetchone()"""
    all_time_usage = db_session.query(func.sum(CradlepointStats.MB_used)).scalar()
    return all_time_usage

def WebSQAOutputObjectInfoByName(cp_name):
    """
    Returns a single dictionary

    {'Average_Usage': 477.39,
    'CP_Name': 'ROA-CP1',
    'Count': 867,
    'Date_First_Seen': '2021-03-28',
    'Date_Last_Seen': '2021-10-31',
    'Date_Highest_Usage': '2021-03-28',
    'Highest_Usage': 4791.36,
    'Total_Usage': 413901.2,
    'Xday_Average_Usage': 2314.35}
    """
    cp_info_dict = {}
    stats_schema = CradlepointStatsSchema(many=True)
    max_usage = (
        db_session.query(CradlepointStats.date, func.max(CradlepointStats.MB_used).label('MB_used'))
        .filter(CradlepointStats.Cradlepoint == cp_name)
        .all()
    )
    max_usage_temp = stats_schema.dump(max_usage)
    if sys.version_info[0] > 2:
        max_usage_output = max_usage_temp
    else:
        max_usage_output = max_usage_temp[0]
   
    earliest_date = (
        db_session.query(CradlepointStats.date)
        .filter(CradlepointStats.Cradlepoint == cp_name)
        .order_by(CradlepointStats.date.asc())
        .limit(1)
        .all()
    )
    earliest_date_temp = stats_schema.dump(earliest_date)
    if sys.version_info[0] > 2:
        earliest_date_output = earliest_date_temp
    else:
        earliest_date_output = earliest_date_temp[0]

    latest_date = (
        db_session.query(CradlepointStats.date)
        .filter(CradlepointStats.Cradlepoint == cp_name)
        .order_by(CradlepointStats.date.desc())
        .limit(1)
        .all()
    )
    latest_date_temp = stats_schema.dump(latest_date)
    if sys.version_info[0] > 2:
        latest_date_output = latest_date_temp
    else:
        latest_date_output = latest_date_temp[0]

    total_data_used = (
        db_session.query(func.sum(CradlepointStats.MB_used).label('MB_used'))
        .filter(CradlepointStats.Cradlepoint == cp_name)
        .all()
    )
    total_data_used_temp = stats_schema.dump(total_data_used)
    if sys.version_info[0] > 2:
        total_data_used_output = total_data_used_temp
    else:
        total_data_used_output = total_data_used_temp[0]

    count = (
        db_session.query(func.count(CradlepointStats.MB_used).label('MB_used'))
        .filter(CradlepointStats.Cradlepoint == cp_name)
        .scalar()
    )

    last100_days = (
        db_session.query(CradlepointStats.date,
        func.sum(CradlepointStats.MB_used))
        .filter(CradlepointStats.Cradlepoint == cp_name)
        .group_by(CradlepointStats.date)
        .order_by(CradlepointStats.date.desc())
        .limit(100)
        .all()
    )

    last100_total_usage = 0
    for day in last100_days:
        last100_total_usage += day[1]

    #print(f'earliest_date = {earliest_date}')
    #print(f'earliest date output = {earliest_date_output}')
    #print(f'total_data_used = {total_data_used}')
    #print(f'total data output = {total_data_used_output}')
    #print(f'max_usage = {max_usage}')
    #print(f'max_usage output = {max_usage_output}')
    #print(f'count = {count}')
    cp_info_dict["CP_Name"] = cp_name
    cp_info_dict["Highest_Usage"] = round(max_usage_output[0]['MB_used'],2)
    cp_info_dict["Date_Highest_Usage"] = max_usage_output[0]['date']
    cp_info_dict["Date_First_Seen"] = earliest_date_output[0]['date']
    cp_info_dict["Date_Last_Seen"] = latest_date_output[0]['date']
    cp_info_dict["Total_Usage"] = round(total_data_used_output[0]['MB_used'],2)
    cp_info_dict["Count"] = count
    cp_info_dict["Average_Usage"] = round(total_data_used_output[0]['MB_used']/count, 2)
    cp_info_dict["Xday_Average_Usage"] = round(last100_total_usage/100, 2)
    return cp_info_dict

def WebSQAShowUsageByName(cp_name, sort_by_value, sort_order_value, response_limit, min_data_usage):
    """
    Returns a list of dictionaries with the resulting fields based on the input instructions

    [{'MB_used': 146081.44686603546, 'date': '2023-02-10'},
    {'MB_used': 94065.97899150848, 'date': '2022-09-17'},
    {'MB_used': 2152.91575050354, 'date': '2023-05-04'},
    {'MB_used': 1270.8917436599731, 'date': '2022-11-19'},
    {'MB_used': 1253.016933441162, 'date': '2023-07-14'},
    {'MB_used': 1193.722201347351, 'date': '2023-05-03'}]
    """

    debug=False
    if debug:
        #print(f'min_data_usage original = {min_data_usage}')
        pass
    if min_data_usage:
        min_data_usage = int(min_data_usage)
    else:
        min_data_usage = 0
    if debug:
        #print(f'cp_name = {cp_name}')
        #print(f'sort by value = {sort_by_value}')
        #print(f'sort order value = {sort_order_value}')
        #print(f'min_data_usage = {min_data_usage}')
        #print(f'min_usage_data_type = {type(min_data_usage)}')
        pass
    if sort_by_value == 'Usage':
        sort_by_value = CradlepointStats.MB_used
    elif sort_by_value == "Date":
        sort_by_value = CradlepointStats.date
    if sort_order_value.lower() == "asc":
        sort_order_value = asc
    elif sort_order_value.lower() == "desc":
        sort_order_value = desc
    
    if debug:
        #print(f'NEW sort by value = {sort_by_value}')
        pass
    if min_data_usage != 0 and sort_by_value != 'date':
        #valid query: SELECT MB_used, date FROM cradlepoint_stats WHERE Cradlepoint = "ROA-CP1" AND MB_used > 1000 ORDER BY MB_used DESC LIMIT 9999;
        #usage_query = 'SELECT MB_used, date FROM cradlepoint_stats WHERE Cradlepoint = "{}" AND MB_used > {} ORDER BY {} {} LIMIT {}'.format(cp_name, min_data_usage, sort_by_value, sort_order_value, response_limit)
        usage_query = (
            db_session.query(CradlepointStats.date, CradlepointStats.MB_used)
            .filter(and_(CradlepointStats.Cradlepoint == cp_name, CradlepointStats.MB_used > min_data_usage))
            .order_by(sort_order_value(sort_by_value))
            .limit(response_limit)
        )
    elif min_data_usage == 0:
        #usage_query = 'SELECT MB_used, date FROM cradlepoint_stats WHERE Cradlepoint = "{}" ORDER BY {} {} LIMIT {}'.format(cp_name, sort_by_value, sort_order_value, response_limit)
        usage_query = (
            db_session.query(CradlepointStats.date, CradlepointStats.MB_used)
            .filter(CradlepointStats.Cradlepoint == cp_name)
            .order_by(sort_order_value(sort_by_value))
            .limit(response_limit)
        )
    else:
        print('Your query is broken')
   
    cp_usage_data_original = usage_query.all()
    stats_schema = CradlepointStatsSchema(many=True)
    cp_usage_data = stats_schema.dump(cp_usage_data_original)

    if debug:
        for row in cp_usage_data:
            #print(f'row["MB_used"] = {row["MB_used"]}')
            #print(f'row["date"] = {row["date"]}')
            pass
    
    if sys.version_info[0] > 2:
        return cp_usage_data
    else:
        return cp_usage_data[0]

def WebSQAAllDeviceUsageForADay(day, sort_by_value, sort_order_value):
    #System Wide All devices by day
    """
    Returns a list of dictionaries of each device and its usage that day sorted any way we want (alphabetical, date asc, date desc)
    
    [{'Cradlepoint': 'YRW-CP1 New', 'MB_used': 633.8155145645142, 'date': '2023-08-15'},
    {'Cradlepoint': 'YRA-CP1', 'MB_used': 802.9132556915283, 'date': '2023-08-15'},
    {'Cradlepoint': 'YMA-CP1', 'MB_used': 834.0391359329224, 'date': '2023-08-15'},
    {'Cradlepoint': 'XWA-CP1', 'MB_used': 947.1502056121826, 'date': '2023-08-15'},
    {'Cradlepoint': 'WSA-CP1', 'MB_used': 885.6480417251587, 'date': '2023-08-15'},
    {'Cradlepoint': 'WDC-CP1', 'MB_used': 900.5425500869751, 'date': '2023-08-15'}]
    """
    if sort_by_value == "Name":
        sort_by_value = CradlepointStats.Cradlepoint
    elif sort_by_value == "Usage":
        sort_by_value = CradlepointStats.MB_used
    if sort_order_value.lower() == "asc":
        sort_order_value = asc
    elif sort_order_value.lower() == "desc":
        sort_order_value = desc
    usage_query = (
            db_session.query(CradlepointStats.Cradlepoint, CradlepointStats.date, CradlepointStats.MB_used)
            .filter(CradlepointStats.date == day)
            .order_by(sort_order_value(sort_by_value))
    )
    cp_usage_data_original = usage_query.all()
    stats_schema = CradlepointStatsSchema(many=True)
    cp_usage_data = stats_schema.dump(cp_usage_data_original)
    if sys.version_info[0] > 2:
        return cp_usage_data
    else:
        return cp_usage_data[0]

if __name__ == "__main__":
    top = WebSQAAllDeviceUsageForADay(day="2023/08/15", sort_by_value="Name", sort_order_value="DESC")
    pprint(top)
