#!/usr/bin/env python3
from flask import Flask, request, render_template, redirect
from flask_bootstrap import Bootstrap
import os, pickle, base64, time
import CXX
import PTP
import TNT

app = Flask(__name__)
Bootstrap(app)
app.secret_key = os.urandom(32)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

try:
    FLAG = open('./flag.txt', 'r').read() # Flag is here!!
except:
    FLAG = '[**FLAG**]'

INFO = ['name', 'userid', 'password']

@app.route('/', methods=['GET', 'POST'])
def main():
    if request.method == "GET":
        return render_template("index.html")
    elif request.method == "POST":
        return render_template("index.html")
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == "GET":
        return render_template("dashboard.html", posts=["data", "data2", "data3"])
    elif request.method == "POST":
        target_url_host = ""
        target_url_full = ""
        method = ""
        host = ""
        schema = ""
        data = ""
        _result = request.form

        # invlaid check
        for _rk, _rv in _result.items():
            print(_rk, _rv)
            # # result is set of value is method:, schema:, host:, data: check
            if _rk == "method":
                if (_rv).upper() != "POST" and (_rv).upper() != "GET":
                    return redirect(location='/')
                else:
                    method = (_rv).upper()
            elif _rk == "schema":
                if (_rv).lower() != "http" and (_rv).lower() != "https":
                    return redirect(location='/')
                else:
                    schema = (_rv).lower()
            elif _rk == "host":
                if (_rv) == "":
                    return redirect(location='/')
                else:
                    host = (_rv)
            elif _rk == "p_data":
                if (_rv) == "":
                    return redirect(location='/')
                else:
                    data = (_rv)
        target_url_host = schema + "://" + host
        target_url_full = target_url_host + "/"+ data


        # tor relay chain connection
        tnt = TNT.TNT()
        # tnt.relay()
        time.sleep(0.5)
        # assert tor_proc.is_alive(), "Tor is not running"


        cxx = CXX.CXX(TARGET_URL=target_url_host, TARGET_METHOD=method)
        if cxx is None:
            return redirect(location='/')

        cxx.get_all_url_parse()
        cxx.cehck_method()
        cxx.inner_script_gadget()
        
               
        origin_url_list = (cxx.URL_TEXT).split("\n")
        origin_url_source_list = (cxx.URL_SOURCE_TEXT).split("\n")
        origin_url_ext_list = (cxx.URL_ASSET_TEXT).split("\n")

        
        # SECURITY, ENV key parser URL_SECURITY_STRUCT
        security_check = cxx.URL_SECURITY_STRUCT

        # logical bug innerscript
        logicalbug_inner_script = (cxx.URL_INNER_SCRIPT).split("[**]")

        ptp = PTP.PTP(method, host, logicalbug_inner_script, security_check)
        ptp.seed_pool()
        ptp.mutation()
        ptp.ptpfuzz()

        crash = ptp.crash


        return render_template(
            template_name_or_list="dashboard.html",
            crash = crash,
            lis = logicalbug_inner_script,
            sec = security_check,
            oul=origin_url_list,
            ouls=origin_url_source_list,
            oule=origin_url_ext_list
        )
        # return "zer0luck"



app.run(host='127.0.0.1', port=8000)