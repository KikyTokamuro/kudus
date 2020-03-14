#!/usr/bin/python3

import re
import json
import argparse
import requests
from termcolor import colored

class Kudus:
    def __init__(self, url):
        self.url = url.replace("http://","").replace("https://","")
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130328 Firefox/21.0",
            "Keep-Alive": "300",
            "Connection": "keep-alive",
            "Cache-Control": "max-age=0"
        }

        self.subdomains = []
        
        print(colored("Starting search domains...", "green"))


    def __get(self, requrl):
        try:
            resp = requests.get(requrl, headers=self.headers, allow_redirects=False, timeout=60)
        except Exception as err:
            print(f"Other error occured: {err}")
        else:
            if resp.status_code == 404:
                print(colored(f"{resp.content}", "red"))
                quit()
            else:
                return resp.content

    # Get subdomains from threatcrowd.org
    def __threatcrowd(self):
        threatcrowd = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.url}"

        print(colored("Search subdomains on threatcrowd.org", "magenta"))

        resp = self.__get(threatcrowd)
        links = json.loads(resp.decode("utf8"))["subdomains"]

        for link in links:
            self.subdomains.append(link.strip())

    # Get subdomains from virustotal.com
    def __virustotal(self):
        virustotal = f"https://www.virustotal.com/ui/domains/{self.url}/subdomains?limit=40"

        print(colored("Search subdomains on virustotal.com", "magenta"))        
        
        resp = self.__get(virustotal)
        links = json.loads(resp.decode("utf8"))["data"]

        for link in links:
            self.subdomains.append(link["id"].strip())

    # Get subdomains from certspotter.com
    def __certspotter(self):
        certspotter = f"https://api.certspotter.com/v1/issuances?domain={self.url}&include_subdomains=true&expand=dns_names"

        print(colored("Search subdomains on certspotter.com", "magenta"))        
        
        resp = self.__get(certspotter)
        links = json.loads(resp.decode("utf8"))

        for link in links:
            for l in link["dns_names"]:
                self.subdomains.append(l.strip())

    # Get subdomains from certspotter.com
    def __hackertarget(self):
        hackertarget = f"https://api.hackertarget.com/hostsearch/?q={self.url}"

        print(colored("Search subdomains on hackertarget.com", "magenta"))        
        
        resp = self.__get(hackertarget)
        links = re.sub(",.*", "", resp.decode("utf8"))
        
        self.subdomains.extend(links.split("\n"))

    # Get subdomains from threatminer.com
    def __threatminer(self):
        threatminer = f"https://api.threatminer.org/v2/domain.php?q={self.url}&rt=5"
        
        print(colored("Search subdomains on threatminer.org", "magenta"))

        resp = self.__get(threatminer)
        links = json.loads(resp.decode("utf8"))

        if links["status_code"] != "404":
            for link in links["results"]:
                self.subdomains.append(link.strip())

    # Get subdomains from crt.sh
    def __crtsh(self):
        crtsh = f"https://crt.sh/?q=.{self.url}&output=json"
        
        print(colored("Search subdomains on crt.sh", "magenta"))

        resp = self.__get(crtsh)
        links = json.loads(resp.decode("utf8"))

        if len(links) != 0:
            for link in links:
                if "\n" in link["name_value"]:
                    self.subdomains.extend(link["name_value"].split("\n"))
                else:
                    self.subdomains.append(link["name_value"])

    # Delete other trash from subdomains list
    def __deleteTrash(self):
        # Delete *
        self.subdomains = filter(lambda s: not s.startswith('*'), self.subdomains)

        # Delete foreign domains
        self.subdomains = filter(lambda s: self.url in s, self.subdomains)

        # Delete replies
        self.subdomains = list(dict.fromkeys(self.subdomains))
        
        
    # Run subdomain search
    def run(self):
        self.__threatcrowd()
        self.__virustotal()
        self.__certspotter()
        self.__hackertarget()
        self.__threatminer()
        self.__crtsh()

        self.__deleteTrash()

        for s in self.subdomains:
            print(colored(s, "green"))

# Banner
def banner():
    print(colored("""
     _   __          _           
    | | / /         | |          
    | |/ / _   _  __| |_   _ ___ 
    |    \| | | |/ _` | | | / __|
    | |\  \ |_| | (_| | |_| \__ \\
    \_| \_/\__,_|\__,_|\__,_|___/ v0.1""", "magenta"))

    print(colored("""
    Author: KikyTokamuro
    Twitter: @kiky_tokamuro\n""", "yellow"))

    
if __name__ == "__main__":
    banner()

    # Parsing args
    parser = argparse.ArgumentParser(description="Website subdomains scanner")
    parser.add_argument("-u", "--url", dest="url", help="Url for scan", type=str, required=True)
    args = parser.parse_args()

    # Run
    kudus = Kudus(args.url)
    kudus.run()
