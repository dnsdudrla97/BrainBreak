import requests, string, signal, sys, os, re, random
from bs4 import BeautifulSoup

class PTP():
    def __init__(self, target_method, target_url_host, innerScript,security_check):
        self.innerScript = innerScript
        self.security_check = security_check
        self.OriginHost = target_url_host
        self.OriginMethod = target_method
        self.seed = list()
        self.testcase = list()
        self.crashCount = 0
        self.crash = list()
        self.PROXIES = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

    
    # seed pool
    def seed_pool(self):
        try:
            is_tmp = ""
            for iS in self.innerScript:
                if iS.find('window') != -1:
                    es_tmp = iS[iS.find('window')+7:iS.find("=")] + "\n"
                    if (es_tmp.find("]") != -1):
                        is_tmp += es_tmp[:es_tmp.find("]") + 1] +"\n"
                    else:
                        is_tmp += es_tmp                
                
            self.seed = list(set(list(is_tmp.split("\n"))))
        except:
            pass

    def random_ascii(self):
        size = random.randint(1,16)
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))

    # mutation
    def mutation(self):
        try:
            for s_k, s_v in self.security_check.items():
                if s_k.find(self.OriginHost) != -1:
                    if s_k.find("?") != -1 or s_k.find("&") != -1:
                        self.testcase.append(s_k.replace(s_k[s_k.find("?")+1:s_k.find("=")], random.choice(self.seed)))
                    else:
                        s_tmp = s_k + "/?" + random.choice(self.seed) + "=" + self.random_ascii()
                        for i in range(1,random.randint(2, 10)):
                            s_tmp += "&" + random.choice(self.seed) + "=" + self.random_ascii()
                        self.testcase.append(s_tmp)
                else:
                    pass
        except:
            pass
    # fuzz
    def ptpfuzz(self):
        print("[*] Start PTP Fuzzing")
        for tc in self.testcase:
            try:
                if self.OriginMethod == "GET":
                    r = requests.get(tc, proxies=self.PROXIES)
                elif self.OriginMethod == "POST":
                    r = requests.post(tc, proxies=self.PROXIES)
                else:
                    r = requests.options(tc, proxies=self.PROXIES)
                if r.status_code != 200:
                    print(f"[*] COUNT:{str(self.crashCount)}")
                    print(f"[!!{r.status_code}]{tc}is vulnerable")
                    self.crashCount += 1
                    self.crash.append(f"[{r.status_code}] => {tc}")
                else:
                    pass
            except:
                pass
        print("[*] Finish PTP Fuzzing")
        





