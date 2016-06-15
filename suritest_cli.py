#!/usr/bin/python
import requests, sys, json, time

if len(sys.argv) < 3:
        print "usage : %s <server> <pcap file> [ruleset file]" % (sys.argv[0])
        print "%s http://127.0.0.1:5000 test.pcap test.rules" % (sys.argv[0])
        sys.exit(0)

host = sys.argv[1]
ruleset_data = ""
pcap_file = sys.argv[2]
if len(sys.argv) >= 4:
        ruleset_file = sys.argv[3]
        with open(ruleset_file, "rb") as fhandle:
                 ruleset_data = fhandle.read()

with open(pcap_file, "rb") as pcap_handle:
        headers = {"content-type":"application/x-www-form-urlencoded"}
        files = {"pcap":pcap_handle}
        data = {"ruleset":ruleset_data,"title":"test"}
        r_handle = requests.post(host+"/api/new/", files=files, data=data)
        r_data = json.loads(r_handle.text)
        if r_data["id"] != 0:
                a_id = r_data["id"]
                while True:
                         r_handle = requests.get(host+"/api/analysis/"+str(a_id))
                         r_data = json.loads(r_handle.text)
                         if r_data["analysis"]["status"] == 2:
                                 print "Analysis finished"
                                 if r_data["analysis"]["hit"] == 1:
                                         print "\tRULE HIT!"
                                 if "hits" in r_data:
                                         for rulename in r_data["hits"]:
                                                 print "\t"+rulename
                                 break
                         time.sleep(1)
