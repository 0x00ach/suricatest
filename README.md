# suricatest
Python-based Suricata rules test platform, for development or PCAP detection. It allows:
- submitting PCAP files and get detection results (rules, raw outputs, etc.);
- submitting PCAP and RULESET and get detection results and debug information;
- viewing old results through the web interface (review analyses, download PCAP/outputs, search, etc.);
- using a simple HTTP API to work with commandline scripts or just with other tools.

The webserver runs with python Flask and communicates with the suricata service with UNIX socket using SuricataSC. For custom rulesets new suricata instances are started using the commandline interface. Results are stored in an sqlite3 database.

The code is really dirty, I'm aware of it :].

# install
I made a tiny install.sh script (debian/ubuntu) which:
- installs dependencies (python/suricata);
- installs suricata 3.0 from source;
- patches configuration files (sed :']);
- configures a suricata service (init.d and default scripts).

# config
Place your rules into the "rules" folder, any ".rules" script will be loaded. Just restart the "suricata" service.

By default, the web service will run on 0.0.0.0:5000.

# suritest_cli.py

Simple request-based script which remotely sends PCAP files (and ruleset if any) to the server, waits for results and displays matched rules.
