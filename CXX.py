import requests, string, signal, sys, os, re
from bs4 import BeautifulSoup

class CXX:
    def __init__(self, TARGET_URL):
        self.ASSET_EXT = ['pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'ico', 'webp', 'mp3', 'mp4', 'ogg', 'wav', 'flac', 'aac', 'wma', 'm4a', 'm4v', 'mov', 'wmv', 'avi', 'mpg', 'mpeg', 'mkv', '3gp', '3g2', 'm4v', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r', 'm4v', 'm4s', 'm4v', 'm4a', 'm4p', 'm4b', 'm4r']
        self.SOURCE_EXT = ['js', 'css']
        self.TARGET_URL = TARGET_URL
        self.BAD_URL = TARGET_URL
        self.URL_SECURITY_STRUCT = dict()
        self.DOMAIN = list()
        self.URL_TEXT = "" # url parser text
        self.URL_ASSET_TEXT = ""
        self.URL_SOURCE_TEXT = ""
        self.URL_INNER_SCRIPT = ""

    # [API:INNER] TARGET_URL schema check
    def schema_check(self, url):
        try:
            if ((url.find(self.BAD_URL) != -1) and (url.find("https")) != -1):
                return url
            elif (url.find('http') | url.find('https')) == -1:
                url = self.TARGET_URL + url
            return url
        except:
            return url

    # [API:INNER] method check
    def cehck_method(self):
        print(f"[*] Method check")
        try:
            for i in self.URL_TEXT.split('\n'):
                try:
                    res_opt = requests.options(i)
                except:
                    print(f"EXCEPT: {res_opt.url}")
                    continue
                headers = res_opt.headers
                # key-value 
                self.URL_SECURITY_STRUCT[i] = {"SECURITY":{},"COOKIE":{}, "ENV":{}, "EXTEND":{}}
                self.security_check(g_url_sec_check_dict=self.URL_SECURITY_STRUCT, urlName=i, url=headers)
            
            for i in self.URL_ASSET_TEXT.split('\n'):
                try:
                    res_opt = requests.options(i)
                except:
                    print(f"EXCEPT: {res_opt.url}")
                    continue
                headers = res_opt.headers
                # key-value 
                self.URL_SECURITY_STRUCT[i] = {"SECURITY":{},"COOKIE":{}, "ENV":{}, "EXTEND":{}}
                self.security_check(g_url_sec_check_dict=self.URL_SECURITY_STRUCT, urlName=i, url=headers)
            
            for i in self.URL_SOURCE_TEXT.split('\n'):
                try:
                    res_opt = requests.options(i)
                except:
                    print(f"EXCEPT: {res_opt.url}")
                    continue
                headers = res_opt.headers
                # key-value 
                self.URL_SECURITY_STRUCT[i] = {"SECURITY":{},"COOKIE":{}, "ENV":{}, "EXTEND":{}}
                self.security_check(g_url_sec_check_dict=self.URL_SECURITY_STRUCT, urlName=i, url=headers)
        except:
            pass

    # security check pattern with re
    def security_check(self, g_url_sec_check_dict, urlName, url={}):
        try:
            for url_key, url_value in url.items():
                # iframe security check pattern "X-Frame-Options"
                if (url_key.find("X-Frame-Options") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["X-Frame-Options"] = url_value
                # content security policy "Content-Security-Policy"
                elif (url_key.find("Content-Security-Policy") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["Content-Security-Policy"] = url_value
                # X-XSS-Protection
                elif (url_key.find("X-XSS-Protection") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["X-XSS-Protection"] = url_value
                # Access-Control-Allow-Origin
                elif (url_key.find("Access-Control-Allow-Origin") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["Access-Control-Allow-Origin"] = url_value
                # Access-Control-Allow-Credentials
                elif (url_key.find("Access-Control-Allow-Credentials") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["Access-Control-Allow-Credentials"] = url_value
                # Access-Control-Expose-Headers
                elif (url_key.find("Access-Control-Expose-Headers") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["Access-Control-Expose-Headers"] = url_value
                # Access-Control-Max-Age
                elif (url_key.find("Access-Control-Max-Age") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["Access-Control-Max-Age"] = url_value
                # Access-Control-Allow-Methods
                elif (url_key.find("Access-Control-Allow-Methods") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["Access-Control-Allow-Methods"] = url_value
                # Access-Control-Allow-Headers
                elif (url_key.find("Access-Control-Allow-Headers") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["Access-Control-Allow-Headers"] = url_value
                # COOP: Cross-Origin-Opener-Policy
                elif (url_key.find("Cross-Origin-Opener-Policy") != -1):
                    g_url_sec_check_dict[urlName]["SECURITY"]["Cross-Origin-Opener-Policy"] = url_value
                # Server
                elif (url_key.find("Server") != -1):
                    g_url_sec_check_dict[urlName]["ENV"]["Server"] = url_value
                # Allow method
                elif (url_key.find("Allow") != -1):
                    g_url_sec_check_dict[urlName]["ENV"]["Allow-Methid"] = url_value
                # setCookies
                elif (url_key.find("set-cookie") != -1):
                    g_url_sec_check_dict[urlName]["COOKIE"]["set-cookie"] = url_value
        except:
            pass
        # print(self.URL_SECURITY_STRUCT)
    
    # csp check
    def csp_check(self):
        print("[*] CSP check")
        for url_key, url_value in self.URL_SECURITY_STRUCT.items():
            if url_value["SECURITY"].get("Content-Security-Policy") is not None:
                _=(url_value['SECURITY']['Content-Security-Policy']).split('\';')
                print(_)

    # inner script gadget find
    def inner_script_gadget(self):
        # value of  url_sec_check dict key
        try:
            for url_key, url_value in self.URL_SECURITY_STRUCT.items():
                if url_value["SECURITY"].get("X-XSS-Protection") is None or url_value["SECURITY"].get("X-XSS-Protection") == "0":
                    req = requests.get(url_key)
                    soup = BeautifulSoup(req.text, 'html.parser')
                    for script in soup.find_all('script'):
                        self.URL_INNER_SCRIPT += f"[**]//[host]:{url_key}[/host]\n<script>{script.text}</script>[**]\n"
                else:
                    pass
        except:
            pass

    # subdomain parser
    def subdomain_parser(self):
        print("[*] Subdomain parser")

        # hostname filter
        for i in ((self.URL_ASSET_TEXT).split('\n')):
            try:
                self.DOMAIN.append(((i).split("/"))[2])
            except:
                continue
        for i in ((self.URL_SOURCE_TEXT).split('\n')):
            try:
                self.DOMAIN.append(((i).split("/"))[2])
            except:
                continue
        for i in ((self.URL_TEXT).split('\n')):
            try:
                self.DOMAIN.append(((i).split("/"))[2])
            except:
                continue
        print(list(set(self.DOMAIN)))

    # cookie parser
    def cookie_parser(self):
        print("[*] Cookie parser")
        # self.URL_SECURITY_STRUCT
        for url_key, url_value in self.URL_SECURITY_STRUCT.items():
            if url_value["COOKIE"].get("set-cookie") is not None:
                print(url_value["COOKIE"]["set-cookie"])


    # [API] TARGET_URL in ALL URL
    def get_all_url_parse(self):        
        print("=========================================== START ===========================================")
        try:
            req = requests.get(self.TARGET_URL)
            
            # response statuc code check 400, 500 is return
            if req.status_code == 400 or req.status_code == 500:
                return   
            saveHtml = req.text
            soup = BeautifulSoup(saveHtml, 'html.parser')

            current_url = []
            src_list = ["audio", "embed", "iframe", "img", "input", "script", "source", "track", "video"]

            src_allow_list = []
            for i in src_list:
                if saveHtml.find(i) != -1:
                    src_allow_list.append(i)

            for i in src_allow_list:
                for j in soup.find_all(i):
                    _j = j.get('src')
                    if _j is not None:
                        # print(schema_check(_j))
                        current_url.append(self.schema_check(_j))

            # href parser
            for link in soup.find_all('a'):
                # filter is not http and https
                _f = link.get('href')
                if _f is not None:
                    # print(schema_check(_f))
                    current_url.append(self.schema_check(_f))

            # multiple remove url
            current_url = list(set(current_url))       

            # check asset ext is in list
            for i in current_url:
                block = i.split('.')
                for j in block:
                    if j in self.ASSET_EXT:
                        self.URL_ASSET_TEXT += f"{i}\n"
                        current_url.remove(i)
                    if j in self.SOURCE_EXT:
                        self.URL_SOURCE_TEXT += f"{i}\n"
                        current_url.remove(i)

            for i in current_url:
                print(i)
                self.URL_TEXT += i + "\n"
            print(f"====================== finish ======================")
        except:
            pass

