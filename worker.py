#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, random, time, md5, sys, signal
import sqlite3, suricatasc, atexit, json
import traceback, hashlib
from subprocess import call
from multiprocessing import Pool, Queue
from flask import Flask, render_template, url_for, request, abort, send_file, redirect
from werkzeug.utils import secure_filename

"""

    #####################################
        CONFIG / GLOBALS
    #####################################

"""

tabschema = ["""CREATE TABLE analysis(id INTEGER PRIMARY KEY AUTOINCREMENT, title varchar(256), ruleset TEXT not null, status INTEGER default 0, date INTEGER, hit INTEGER, pcap_name varchar(256), file_path varchar(260));""","""CREATE TABLE suricata_output(id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER, file_name VARCHAR(32), file_path VARCHAR(260));""","""CREATE TABLE rule_matched(analysis_id INTEGER, rule_id INTEGER)""","""CREATE TABLE rule(id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(260));"""]
base = os.path.dirname(os.path.abspath(__file__))
suricata_norules_config_path = os.path.join(base,"suricataconf","suricata_norules.yaml")
output_folder = os.path.join(base, "results")
database_file = os.path.join(base, "suri.db")
storage_folder = os.path.join(base, "storage")
suricata_socket_file = "/var/run/suricata/suricatest.socket"
debug = True

if not os.path.exists(output_folder):
    os.mkdir(output_folder) 
if not os.path.exists(storage_folder):
    os.mkdir(storage_folder)
    
"""

    #####################################
        DB CONTROLLER
    #####################################

"""

class database_handler:
    """
        DB handling
    """
    def __init__(self, db_file):
        self.db_file = db_file
        self.cursor = None
        self.connection = None
        if not os.path.isfile(self.db_file):
            self.create_db()
        self.connect_db()
        self.close_db()
    def create_db(self):
        global tabschema
        if self.connect_db() == False:
            return False
        for row in tabschema:
            self.cursor.execute(row)
        self.connection.commit()
        self.close_db()
    def connect_db(self):
        if self.connection is not None:
            return True
        try:
            self.connection = sqlite3.connect(self.db_file, check_same_thread=False)
            self.cursor = self.connection.cursor()
        except Exception as e:
            app.logger.error(e)
            self.connection = None
            self.cursor = None
            return False
        return True
    def close_db(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        return True
    """
        Analysis
    """
    def create_analysis(self, title, pcap_name, pcap_path, ruleset):
        created_id = None
        self.connect_db()
        try:
            self.cursor.execute("INSERT INTO analysis(title, pcap_name, file_path, ruleset, status, date, hit) VALUES(?,?,?,?,0,?,0);",(title, pcap_name, pcap_path, ruleset, int(time.time())))
            self.connection.commit()
            created_id = self.cursor.lastrowid
        except Exception as e:
            app.logger.error(e)
            self.connection.rollback()
            pass
        self.close_db()
        return created_id
    def delete_analysis(self, analysis_id):
        self.connect_db()
        stat = False
        try:
            self.cursor.execute("DELETE FROM rule_matched WHERE analysis_id = ?",[analysis_id])
            self.cursor.execute("DELETE FROM suricata_output WHERE analysis_id = ?",[analysis_id])
            self.cursor.execute("DELETE FROM analysis WHERE id = ?",[analysis_id])
            self.connection.commit()
            stat = True
        except Exception as e:
            app.logger.error(e)
            pass
        self.close_db()
        return stat
    def get_analysis_data(self, analysis_id):
        retv = None
        self.connect_db()
        try:
            self.cursor.execute("SELECT status, pcap_name, file_path, ruleset, title, date, hit, id FROM analysis WHERE id = ?", [analysis_id])
            data = self.cursor.fetchone()
            retv = {}
            retv["status"] = data[0]
            retv["pcap_name"] = data[1]
            retv["pcap_file"] = data[2]
            retv["ruleset"] = data[3]
            retv["title"] = data[4]
            retv["date"] = data[5]
            retv["hit"] = data[6]
            retv["id"] = data[7]
        except Exception as e:
            app.logger.error(e)
            pass        
        self.close_db()
        return retv
    def set_analysis_started(self, analysis_id):
        self.connect_db()
        stat = False
        try:
            self.cursor.execute("UPDATE analysis SET status = 1 WHERE id = ?", [analysis_id])
            self.connection.commit()
            stat = True
        except Exception as e:
            app.logger.error(e)
            self.connection.rollback()
            pass        
        self.close_db()
    def set_analysis_finished(self, analysis_id):
        self.connect_db()
        stat = False
        try:
            self.cursor.execute("UPDATE analysis SET status = 2 WHERE id = ?", [analysis_id])
            self.connection.commit()
            stat = True
        except Exception as e:
            app.logger.error(e)
            self.connection.rollback()
            pass        
        self.close_db()
        return stat
    def get_notfinished_analyses(self):
        self.connect_db()
        retv = None
        try:
            self.cursor.execute("SELECT id FROM analysis WHERE status <> 2")
            items = self.cursor.fetchall()
            retv = []
            for item in items:
                retv.append(item[0])
        except Exception as e:
            app.logger.error(e)
            pass
        self.close_db()
        return retv
    def search_analyses(self, needle="", rule_id=0, max_count=30, start_offset=0):
        retv = None
        self.connect_db()
        try:
            if rule_id != 0:
                self.cursor.execute("SELECT id, title, status, hit, date FROM analysis a, rule_matched m WHERE m.rule_id = ? AND a.id = m.analysis_id ORDER BY date DESC LIMIT ?,?",[rule_id,start_offset,max_count])
            elif len(needle) < 5:
                self.cursor.execute("SELECT id, title, status, hit, date FROM analysis ORDER BY date DESC LIMIT ?,?",[start_offset,max_count])
            else:
                wild = '%'+needle.lower()+'%'
                self.cursor.execute("SELECT id, title, status, hit, date FROM analysis WHERE LOWER(pcap_name) like ? OR LOWER(title) like ? OR LOWER(ruleset) like ? or id IN (SELECT analysis_id FROM rule_matched m, rule r WHERE LOWER(r.name) LIKE ? AND r.id = rule_id) ORDER BY date DESC LIMIT ?,?",[wild,wild,wild,wild,start_offset,max_count])
            items = self.cursor.fetchall()
            retv = []
            for item in items:
                tmp = {}
                tmp["id"] = item[0]
                tmp["title"] = item[1]
                tmp["status"] = item[2]
                tmp["hit"] = item[3]
                tmp["date"] = item[4]
                retv.append(tmp)
        except Exception as e:
            app.logger.error(e)
            pass
        self.close_db()
        return retv
    """
        Suricata outputs
    """
    def add_analysis_suricata_output(self, analysis_id, logfile, file_path):
        created_id = None
        self.connect_db()
        try:
            self.cursor.execute("INSERT INTO suricata_output(analysis_id, file_name, file_path) VALUES(?,?,?)",[analysis_id, logfile, file_path])
            self.connection.commit()
            created_id = self.cursor.lastrowid
        except Exception as e:
            app.logger.error(e)
            self.connection.rollback()
            pass
        self.close_db()
        return created_id
    def get_suricata_output(self, output_id):
        self.connect_db()
        retv = None
        try:
            self.cursor.execute("SELECT file_name, file_path FROM suricata_output WHERE id = ?",[output_id])
            item = self.cursor.fetchone()
            if item:
                retv = {"file_name":item[0],"file_path":item[1]}
        except Exception as e:
            app.logger.error(e)
            pass
        self.close_db()
        return retv
    def get_analysis_suricata_outputs(self, analysis_id):
        self.connect_db()
        retv = None
        try:
            self.cursor.execute("SELECT file_name, id FROM suricata_output WHERE analysis_id = ?",[analysis_id])
            items = self.cursor.fetchall()
            retv = []
            for item in items:
                x = {"file_name":item[0],"id":item[1]}
                retv.append(x)
        except Exception as e:
            app.logger.error(e)
            pass
        self.close_db()
        return retv
    """
        Suricata rules
    """
    def add_matched_rule_to_analysis(self, analysis_id, rule_name):
        status = False
        self.connect_db()
        try:
            self.cursor.execute("SELECT id FROM rule WHERE name = ?",[rule_name])
            rule_id = 0
            x = self.cursor.fetchone()
            if x:
                rule_id = x[0]
                self.cursor.execute("SELECT * FROM rule_matched WHERE analysis_id = ? AND rule_id = ?",[analysis_id, rule_id])
                x = self.cursor.fetchone()
                if x:
                    self.close_db()
                    return True
            else:
                self.cursor.execute("INSERT INTO rule(name) VALUES(?)",[rule_name])
                rule_id = self.cursor.lastrowid
                app.logger.debug("CREATED RULE %s" % (rule_name))
            self.cursor.execute("INSERT INTO rule_matched(analysis_id, rule_id) VALUES(?,?)",[analysis_id, rule_id])
            self.cursor.execute("UPDATE analysis SET hit = 1 WHERE id = ?",[analysis_id])
            self.connection.commit()
            status = True
        except Exception as e:
            app.logger.error(e)
            self.connection.rollback()
            pass
        self.close_db()
        return status
    def get_analysis_matchs(self, analysis_id):
        self.connect_db()
        retv = None
        try:
            self.cursor.execute("SELECT name FROM rule,rule_matched  WHERE analysis_id = ? AND id = rule_id ORDER BY name",[analysis_id])
            items = self.cursor.fetchall()
            retv = []
            for item in items:
                retv.append(item[0])
        except Exception as e:
            app.logger.error(e)
            pass
        self.close_db()
        return retv
    def get_rules(self):
        self.connect_db()
        retv = None
        try:
            self.cursor.execute("SELECT id, name FROM rule ORDER BY name")
            items = self.cursor.fetchall()
            retv = []
            for item in items:
                retv.append({"id":item[0],"name":item[1]})
        except Exception as e:
            app.logger.error(e)
            pass
        self.close_db()
        return retv
db_handler = database_handler(database_file)

"""

    #####################################
        ANALYSIS
    #####################################

"""

class analysis_handler:
    def __init__(self, pcap_file = "", ruleset = "", pcap_name = "", title = "", analysis_id = 0):
        self.analysis_id = None
        self.pcap_file = None
        self.ruleset = None
        self.output_folder = None
        if analysis_id == 0:
            self.create_analysis(ruleset, pcap_name, pcap_file, title)
        else:
            self.get_analysis_from_db(analysis_id)
    """
        Get or create
    """
    def get_analysis_from_db(self, analysis_id):
        global db_handler, output_folder
        data = db_handler.get_analysis_data(analysis_id)
        if data is None:
            return False
        self.analysis_id = analysis_id
        self.pcap_file = data["pcap_file"]
        self.ruleset = data["ruleset"]
        self.output_folder = os.path.join(output_folder,"result_"+str(self.analysis_id))
        return True
    def create_analysis(self, ruleset, pcap_name, pcap_file, title):
        global db_handler, output_folder
        if pcap_file == "":
            return False
        pcap_id = 0
        if not os.path.exists(pcap_file):
            return False
        self.pcap_file = pcap_file
        self.analysis_id = db_handler.create_analysis(title, pcap_name, pcap_file, ruleset)
        if self.analysis_id is None:
            return False
        self.output_folder = os.path.join(output_folder,"result_"+str(self.analysis_id))
        self.ruleset = ruleset
        return True
    """
        Suricata processing: dispatch to service through UNIX
        socket using SuricataSC library, and then waits.
    """
    def process_pcap_on_service(self):
        global suricata_socket_file
        if not os.path.exists(suricata_socket_file) or self.output_folder is None or not os.path.exists(self.pcap_file):
            print "SURICATASERVICE INVALID DATA ERROR"
            return False
        # create output folder
        if not os.path.exists(self.output_folder):
            os.mkdir(self.output_folder)
        # suricata connection
        try:
            suri = suricatasc.SuricataSC(suricata_socket_file)
            suri.connect()
        except Exception as e:
            print "SURICATASERVICE SOCKET CONNECTION ERROR"
            traceback.print_exc()
            return False
        # suricata command (pcap-file)
        try:
            retcode = suri.send_command("pcap-file", {
                "filename":self.pcap_file,
                "output-dir":self.output_folder,
            })
        except Exception as e:
            suri.close()
            print "SURICATASERVICE COMMAND FAILED"
            traceback.print_exc()
            return False
        # return code
        if not retcode or ("return" in retcode and retcode["return"] != "OK"):
            suri.close()
            print "SURICATASERVICE CODE ERROR %s :: %s" % (retcode["return"], retcode["message"])
            return False
        # TODO: I'm not sure that we're not waiting for ALL jobs to be
        # finished. Maybe we should detect that our actual job has
        # ended well, not all of them. Also, I wonder if multiprocessing
        # will really improve performance and if we should not either use
        # a dedicated dispatcher which polls regularly the new tasks.
        exception_count = 0
        while True:
            try:
                retcode = suri.send_command("pcap-current")
            except Exception as e:
                exception_count += 1
                if exception_count == 10:
                    suri.close()
                    print "SURICATASERVICE EXCEPTIONS MAX REACHED"
                    return False
            if retcode and ("message" in retcode and retcode["message"] == "None"):
                break
            time.sleep(1)
        suri.close()
        return True
    def process_ruleset_on_pcap(self):
        global suricata_norules_config_path
        if self.ruleset == "" or not os.path.exists(self.pcap_file) or self.output_folder is None:
            print "SURICATACMD INVALID DATA ERROR"
            return False
        # create output folder
        if not os.path.exists(self.output_folder):
            os.mkdir(self.output_folder)
        # create ruleset file
        ruleset_file_path = os.path.join(self.output_folder,"ruleset.rules")
        with open(ruleset_file_path,"wb") as f_handle:
            f_handle.write(self.ruleset)
        # commandline
        analysis_cmdline = "suricata -c "+suricata_norules_config_path+" -r "+self.pcap_file+" -s "+ruleset_file_path+" -l "+self.output_folder
        analysis_cmdline_engine = "suricata -c "+suricata_norules_config_path+" -r "+self.pcap_file+" -s "+ruleset_file_path+" --engine-analysis -l "+self.output_folder
        try:
            # start with engine_analysis first, then with regular information
            status = call(analysis_cmdline_engine, shell=True)
            status = call(analysis_cmdline, shell=True)
        except Exception as e:
            print "SURICATACMD PROCESS CREATE ERROR"
            print e
            return False
        # remove ruleset
        os.remove(ruleset_file_path)
        return True
    def run_analysis(self):
        global db_handler
        if self.analysis_id is None:
            return False
        db_handler.set_analysis_started(self.analysis_id)
        if self.ruleset != "" and self.pcap_file != "":
            self.process_ruleset_on_pcap()
        else:
            self.process_pcap_on_service()
        self.get_suricata_reports_and_parse_hits()
        db_handler.set_analysis_finished(self.analysis_id)
        return True
    def get_suricata_reports_and_parse_hits(self):
        global db_handler
        if self.analysis_id is None:
            return False
        logfiles = []
        logfiles.append("alert-debug.log")
        logfiles.append("http.log")
        logfiles.append("fast.log")
        logfiles.append("tls.log")
        logfiles.append("drop.log")
        logfiles.append("rules_analysis.txt")
        logfiles.append("stats.log")
        logfiles.append("rules_fast_pattern.txt")
        if not os.path.exists(os.path.join(self.output_folder, "stats.log")):
            return False
        for logfile in logfiles:
            full_path_file = os.path.join(self.output_folder, logfile)
            if not os.path.exists(full_path_file) or os.stat(full_path_file).st_size == 0:
                continue
            with open(full_path_file, "rb") as f_handler:
                db_handler.add_analysis_suricata_output(self.analysis_id, logfile, full_path_file)
                if logfile == "fast.log":
                    with open(full_path_file, "rb") as f_handler:
                        log_data = f_handler.read()
                        lines = log_data.split("\n")
                        for line in lines:
                            items = line.split("[**]")
                            if len(items) >= 2:
                                rule_name = items[1].strip()
                                db_handler.add_matched_rule_to_analysis(self.analysis_id, rule_name)
        return True
        
"""
    Analysis start wrapper.
"""
def execute_analysis(analysis):
    try:
        print "ANALYSIS #%d STARTED" % (analysis.analysis_id)
        analysis.run_analysis()    
    except Exception as e:
        print e
        return False
    print "ANALYSIS #%d FINISHED" % (analysis.analysis_id)
    return True

"""
    Workers pool
"""
class analysisPool:
    pool = None
    def __init__(self):
        self.pool = Pool()
        atexit.register(self.clear)
    def add_analysis(self, analysis):
        app.logger.info("ANALYSIS #%d QUEUED" % (analysis.analysis_id))
        task_result = self.pool.apply_async(execute_analysis, (analysis,))
    def clear(self):
        self.pool.terminate()
        self.pool.join()

"""
    Re-queue not finished/started analysis on process creation
"""
def restart_interrupted_analyses():
    global db_handler, analysis_pool
    analyses_ids = db_handler.get_notfinished_analyses()
    app.logger.info("RESTARTING ANALYSES")
    for analysis_id in analyses_ids:
        x = analysis_handler(analysis_id = analysis_id)
        analysis_pool.add_analysis(x)
    return True

    

"""

    #####################################
        WEB VIEWS
    #####################################

"""

app = Flask(__name__)

@app.template_filter("ctime")
def timectime(s):
    return time.ctime(s)

@app.errorhandler(404)
def error(error):
    app.logger.error(error)
    return render_template("error.html"), 404

@app.route("/")
def index():
    hits = db_handler.search_analyses()
    return render_template("index.html",
            analyses = hits)

@app.route("/new/", methods=["POST"])
def new_analysis():
    analysis_pcap = None
    analysis_title = None
    analysis_ruleset = None
    pcap_name = None
    pcap_path = None
    if "title" in request.form:
        analysis_title = request.form["title"]
    if "pcap" in request.files:
        analysis_pcap = request.files["pcap"]
    if "ruleset" in request.form:
        analysis_ruleset = request.form["ruleset"]
    if analysis_pcap is None:
        return render_template("index.html", analyses = db_handler.search_analyses())
    pcap_name = analysis_pcap.filename
    pcap_name = secure_filename(str(int(time.time()))+"_"+hashlib.sha256(pcap_name).hexdigest()+".pcap")
    pcap_path = os.path.join(storage_folder, pcap_name)
    analysis_pcap.save(pcap_path)
    x = analysis_handler(pcap_file=pcap_path, ruleset=analysis_ruleset, pcap_name=pcap_name, title=analysis_title)
    analysis_pool.add_analysis(x)
    return render_template("index.html", analyses=db_handler.search_analyses())


@app.route("/analyses/", methods=['GET','POST'])
def browse_analyses():
    rule_filter = 0
    search_filter = ""
    if request.method == "POST":
        if "alerts" in request.form:
            rule_filter = request.form["alerts"]
        elif "needle" in request.form:
            search_filter = request.form["needle"]
    analyses = db_handler.search_analyses(needle=search_filter,
                        rule_id=rule_filter)
    rules = db_handler.get_rules()
    if rules is None:
        rules = []
    return render_template("analyses.html",
            analyses = analyses,
            rules = rules)

@app.route("/analysis/<int:analysis_id>/")
def view_analysis(analysis_id):
    analysis = db_handler.get_analysis_data(analysis_id)
    if analysis is None:
        abort(404)
    results = db_handler.get_analysis_suricata_outputs(analysis_id)
    if results is None:
        results = []
    hits = db_handler.get_analysis_matchs(analysis_id)
    if hits is None:
        hits = []
    return render_template("analysis.html",
            analysis = analysis,
            hits = hits,
            results = results)

@app.route("/delete/<int:analysis_id>")
def delete_analysis(analysis_id):
    db_handler.delete_analysis(analysis_id)
    return redirect(url_for("index"))
    
    
    
"""

    #####################################
        API VIEWS
    #####################################

"""
    
@app.route("/api/")
def apihelp():
    x  = """/api/ => api help
/api/analyses => browse analyses
        POST "filter_rule" : TEXT, filter on rule ID
        POST "filter_text" : TEXT, filter on any text data
/api/analysis/<analysis id>/ => browse analysis
/api/rules/ => browse rules
/api/new/ => submit new analysis
        POST "pcap" : FILE, pcap file
        POST "ruleset" : TEXT, suricata ruleset
        POST "title" : TEXT, analysis title
/api/delete/<analysis id>/ => delete analysis
/getrawoutput/<output id> => get raw file
/pcapdownload/<analysis id> => get analysis pcap file""".replace(" ","&nbsp;").replace("<","&lt;").replace(">","&gt;").replace("\n","<br />")
    return x
    
@app.route("/api/new/", methods=["POST"])
def api_new_analysis():
    analysis_pcap = None
    analysis_title = None
    analysis_ruleset = None
    pcap_name = None
    pcap_path = None
    if "title" in request.form:
        analysis_title = request.form["title"]
    if "pcap" in request.files:
        analysis_pcap = request.files["pcap"]
    if "ruleset" in request.form:
        analysis_ruleset = request.form["ruleset"]
    if analysis_pcap is None:
        return "{'id':0}"
    pcap_name = analysis_pcap.filename
    pcap_name = secure_filename(str(int(time.time()))+"_"+hashlib.sha256(pcap_name).hexdigest()+".pcap")
    pcap_path = os.path.join(storage_folder, pcap_name)
    analysis_pcap.save(pcap_path)
    x = analysis_handler(pcap_file=pcap_path, ruleset=analysis_ruleset, pcap_name=pcap_name, title=analysis_title)
    analysis_pool.add_analysis(x)
    return json.dumps({"id":x.analysis_id})
    
@app.route("/api/rules/")
def api_get_rules():
    rulz = db_handler.get_rules()
    return json.dumps(rulz)

@app.route("/api/delete/<int:analysis_id>")
def api_delete_analysis(analysis_id):
    if db_handler.delete_analysis(analysis_id) == True:
        return "{'status':1}"
    return "{'status':0}"
    
@app.route("/api/analyses/", methods=["GET","POST"])
def api_browse():
    search_filter = ""
    rule_filter = 0
    if request.method == "POST":
        if "filter_rule" in request.form:
            rule_filter = request.form["filter_rule"]
        elif "filter_text" in request.form:
            search_filter = request.form["filter_text"]
    analyses = db_handler.search_analyses(needle=search_filter,
                        rule_id=rule_filter)
    return json.dumps(analyses)
    
@app.route("/api/analysis/<int:analysis_id>/")
def api_view_analysis(analysis_id):
    analysis = db_handler.get_analysis_data(analysis_id)
    if analysis is None:
        abort(404)
    results = db_handler.get_analysis_suricata_outputs(analysis_id)
    if results is None:
        results = []
    hits = db_handler.get_analysis_matchs(analysis_id)
    if hits is None:
        hits = []
    x = {"analysis":analysis,"hits":hits,"suricata_outputs":results}
    return json.dumps(x)
    
@app.route("/api/getrawoutput/<int:output_id>")
def view_suricata_output(output_id):
    item = db_handler.get_suricata_output(output_id)
    if item is None:
        abort(404)
    return send_file(item["file_path"],
            as_attachment=True,
            attachment_filename=item["file_name"])
            
@app.route("/api/pcapdownload/<int:analysis_id>/")
def download_pcap(analysis_id):
    analysis = db_handler.get_analysis_data(analysis_id)
    if analysis is None:
        abort(404)
    return send_file(analysis['pcap_file'],
            as_attachment=True,
            attachment_filename="export_"+str(analysis['id'])+'.pcapng')
            
"""
    MAIN
"""

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 5000
    if "-h" in sys.argv:
        print "%s <host> <port>" % (sys.argv[0])
        print "default values: 0.0.0.0 5000"
        print "\thost\t0.0.0.0"
        print "\tport\t5000"
        sys.exit(0)
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    analysis_pool = analysisPool()
    restart_interrupted_analyses()
    app.run(host=host, port=port, debug=debug)
