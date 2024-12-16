import sys
from flask import Flask, session, render_template, request, url_for, flash, redirect
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
import crp_sqa
from werkzeug.exceptions import abort
if sys.version_info[0] > 2:
    from urllib.parse import urlencode, parse_qs, urljoin, urlparse
    from network_iac_common_utils.sys_environment import environment
else:
    from urllib import urlencode, unquote
    from urlparse import urlparse, parse_qs, urljoin
    sys.path.insert(1, '/var/www/control/Helpers')
    from sys_environment import environment

app = Flask(import_name=__name__)
app.config['SECRET_KEY'] = '565656'
TF = "CradlepointReportingProject"
env = environment()

# some global functions
def get_auth():
    auth = {}
    session_keys = session.keys()
    if "authSwitches" in session_keys:
        auth["session"] = session["authSwitches"]
        if session["authSwitches"]:
            auth["switches"] = True
        else:
            auth["switches"] = False
    else:
        auth["switches"] = False
    if "name" in session_keys:
        auth["authenticated_user"] = session["name"]
    auth["env"] = env.Name
    auth["host_version"] = sys.version_info[0]
    return (auth)

@app.route("/")
def index():
    return render_template("{}/frontpage.html".format(TF), auth=get_auth())

@app.route("/list")
def list_devices():
    return render_template("{}/list_all_devices.html".format(TF), CP_LIST=crp_sqa.SQAListAllObjects(), auth=get_auth())

@app.route("/SystemWideAllTimeStats")
def all_time_stats():
    number_of_days = crp_sqa.SQATotalDays()
    #print(f'number_of_days = {number_of_days}')
    total_data_used = crp_sqa.WebSQAAllTimeSystemDataUsage()
    #print(f'total_data_used = {total_data_used}')
    last_100_total_data_used = crp_sqa.WebSQALastXTotalUsage(day_limit = 100)
    #print(f'Last 100 total data = {last_100_total_data_used}')
    last_100_moving_average = last_100_total_data_used / 100
    #print(f'100 day moving avg = {last_100_moving_average}')
    return render_template("{}/systemwidealltime.html".format(TF),
            TOTAL_DAYS=number_of_days, TOTAL_DATA = total_data_used, MOVING_AVG
            = last_100_moving_average, auth=get_auth())

@app.route("/SystemWideDailyUsage")
def system_wide_daily_usage():
    #returns a list of lists like: [(datetime.date(2023, 9, 5), 56513.85054016113), (datetime.date(2023, 9, 4), 51803.09237766266), (datetime.date(2023, 9, 3), 55848.53785228729)]
    return render_template("{}/systemwidedailyusage.html".format(TF),
            CP_LIST=crp_sqa.WebSQASystemDailyUsage(), auth=get_auth())

@app.route("/top20day")
def top_20day():
    return render_template("{}/top20day.html".format(TF),
            CP_DICT=crp_sqa.SQAFindTopXHighestDays(top_x=20),
            auth=get_auth())

@app.route("/top20alltime")
def top_20alltime():
    return render_template("{}/top20alltime.html".format(TF),
            CP_DICT=crp_sqa.SQAFindTopXDeviceUsage(top_x=20),
            auth=get_auth())

#This route pulls the device summary info and pushes it back to the table
@app.route("/device_summary_data")
def get_device_info():
    return render_template("{}/show_device_summary_data.html".format(TF), CP_DICT=crp_sqa.WebSQAOutputObjectInfoByName(cp_name=request.args["cp"]), auth=get_auth())

#This route loads the device summary page and populates the device drop down list
@app.route("/show_device_summary")
def show_device_summary():
    return render_template("{}/show_device_summary.html".format(TF), CP_LIST=crp_sqa.SQAListAllObjects(), auth=get_auth())

#This route pulls the device usage info and pushes it back to the table
@app.route("/device_usage_data")
def get_device_usage():
    #Data from the web page selection is returned as 
    #ImmutableMultiDict([('cp', 'BAW-CP1'), ('sort_by_value', 'Usage'), ('sort_order_value', 'Asc')])
    #print(f'Requested CP is: {request.args}')
    cp_dict = crp_sqa.WebSQAShowUsageByName(cp_name=request.args["cp"],
                                            sort_order_value=request.args["sort_order_value"],
                                            sort_by_value=request.args["sort_by_value"],
                                            response_limit=request.args["response_limit"],
                                            min_data_usage=request.args["min_data_usage"])
    return render_template("{}/show_device_usage_data.html".format(TF), CP_DICT=cp_dict, auth=get_auth())

#This route loads the device summary page and populates the device drop down list
@app.route("/show_device_usage")
def show_device_usage():
    return render_template("{}/show_device_usage.html".format(TF), CP_LIST=crp_sqa.SQAListAllObjects(), auth=get_auth())

#This route asks the user for a date and then shows all of the cradlepoint usage for that date
@app.route("/all_devices_by_day")
def all_devices_by_day():
    return render_template("{}/all_devices_by_day_main.html".format(TF), auth=get_auth())

#This route asks the user for a date and then shows all of the cradlepoint usage for that date
@app.route("/all_devices_by_day_data")
def all_devices_by_day_data():
    #print(f'Requested date is: {request.args}')
    cp_dict = crp_sqa.WebSQAAllDeviceUsageForADay(day=request.args["day"],
                                                  sort_by_value=request.args["sort_by_value"],
                                                  sort_order_value=request.args["sort_order_value"])
    return render_template("{}/all_devices_by_day_data.html".format(TF), CP_DICT=cp_dict, auth=get_auth())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

