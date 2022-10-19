import io, subprocess, os, stem.process, re, urllib.request, requests, time, json, sys
from datetime import datetime
from stem import CircStatus
from stem.control import Controller

class TNT():
    def __init__(self):
        self.SOCKS_PORT = 9050
        self.CONTROL_PORT = 9051
        self.TOR_PATH = os.path.normpath("/opt/homebrew/Cellar/tor/0.4.7.10/bin/tor")
        self.GEOIPFILE_PATH = os.path.normpath("/opt/homebrew/Cellar/tor/0.4.7.10/share/tor/geoip")

        try:
            subprocess.run(["netstat -nat | grep 9050"], shell=True, check=True)
            pass
        except:
            subprocess.run(["kill -9 $(pidof tor)"], shell=True, check=True)
            self.run()
        

    def run(self):
        # try:
        #     urllib.request.urlretrieve('https://raw.githubusercontent.com/torproject/tor/main/src/config/geoip', GEOIPFILE_PATH)
        # except:
        #     print ('[INFO] Unable to update geoip file. Using local copy.')

        try:
            tor_process = stem.process.launch_tor_with_config(
                config = {
                    'SocksPort' : str(self.SOCKS_PORT),
                    'ControlPort': str(self.CONTROL_PORT),
                    # 'EntryNodes' : '3431940DFB4643A3EE3F4465BFF2655CA9BDEB96',
                    # 'ExitNodes' : '{SG}',
                    'StrictNodes' : '1',
                    'CookieAuthentication' : '1',
                    'MaxCircuitDirtiness' : '60',
                    'GeoIPFile' : 'https://raw.githubusercontent.com/torproject/tor/main/src/config/geoip',
                },
                init_msg_handler = lambda line: print(line) if re.search('Bootstrapped', line) else False,
                tor_cmd = self.TOR_PATH
            )
        except:
            print('[INFO] Unable to start tor process. Please check your tor installation.')
            sys.exit(1)


    def relay(self):
        with Controller.from_port(port = 9051) as controller:
            controller.authenticate()
            for circ in sorted(controller.get_circuits()):
                if circ.status == CircStatus.BUILT:
                    print("Circuit %s (%s)" % (circ.id, circ.purpose))
                    for i, entry in enumerate(circ.path):
                        div = '+' if (i == len(circ.path) - 1) else '|'
                        fingerprint, nickname = entry
                        desc = controller.get_network_status(fingerprint, None)
                        address = desc.address if desc else 'unknown'
                        print(" %s- %s (%s, %s)" % (div, fingerprint, nickname, address))
