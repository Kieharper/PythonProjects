class colour:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

print('\n')
print(colour.PURPLE +
      "##      ##      ##      ##       #######  ")
print("####    ##      ###    ###      ##     ## ")
print("## ##   ##      ## #### ##      ##        ")
print("##  ##  ##      ##  ##  ##      ##        ")
print("##   ## ##      ##      ##      ##        ")
print("##     ###      ##      ##      ##     ## ")
print("##      ##      ##      ##       #######  "
      + colour.END)
print('\n')
print('Version | 1.0 |')
print('Author  | Kieran Harper |')

import os
try:
    import json
except ImportError:
    print('Trying to install required module - json \n')
    os.system('python -m pip install json')
try:
    import requests
except ImportError:
    print('Trying to install required module - requests \n')
    os.system('python -m pip install requests ')
try:
    import webbrowser
except ImportError:
    print('Trying to install required module - webbrowser \n')
    os.system('python -m pip install webbrowser')
try:
    import os
except ImportError:
    print('Trying to install required module - os \n')
    os.system('python -m pip install os')
try:
    import sys
except ImportError:
    print('Trying to install required module - sys \n')
    os.system('python -m pip install sys')
try:
    import urllib3
except ImportError:
    print('Trying to install required module - urllib3 \n')
    os.system('python -m pip install urllib3')
try:
    import argparse
except ImportError:
    print('Trying to install required module - argparse \n')
    os.system('python -m pip install argparse')
try:
    import re
except ImportError:
    print('Trying to install required module - re \n')
    os.system('python -m pip install re')
try:
    import socket
except ImportError:
    print('Trying to install required module - socket \n')
    os.system('python -m pip install socket')
try:
    import dns
except ImportError:
    print('Trying to install required module - dns \n')
    os.system('python -m pip install dns')
try:
    import warnings
except ImportError:
    print('Trying to install required module - warnings \n')
    os.system('python -m pip install warnings')
try:
    import time
except ImportError:
    print('Trying to install required module - time \n')
    os.system('python -m pip install time')
from dns import resolver
from requests.auth import HTTPBasicAuth
from requests import get

url_1 = (get('https://raw.githubusercontent.com/sophos-cybersecurity/solarwinds-threathunt/master/iocs.csv').text)
url1 = ('https://raw.githubusercontent.com/sophos-cybersecurity/solarwinds-threathunt/master/iocs.csv')
url_2 = (get('https://raw.githubusercontent.com/stressboi/hafnium-exchange-splunk-csvs/main/cve-2021-26855-ip.csv').text)
url2 = ('https://raw.githubusercontent.com/stressboi/hafnium-exchange-splunk-csvs/main/cve-2021-26855-ip.csv')
url_3 = (get('https://raw.githubusercontent.com/tesla-consulting/ioc-list/main/iplist.csv').text)
url3 = ('https://raw.githubusercontent.com/tesla-consulting/ioc-list/main/iplist.csv')
url_4 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/CobaltGroup/ips.txt').text)
url4 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/CobaltGroup/ips.txt')
url_5 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/CobaltGroup/hashes.txt').text)
url5 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/CobaltGroup/hashes.txt')
url_6 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/CobaltGroup/domains.txt').text)
url6 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/CobaltGroup/domains.txt')
url_7 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Emotet/domains.txt').text)
url7 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Emotet/domains.txt')
url_8 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Emotet/hashes.txt').text)
url8 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Emotet/hashes.txt')
url_9 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Emotet/ips.txt').text)
url9 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Emotet/ips.txt')
url_10 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Lazarus/domains.txt').text)
url10 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Lazarus/domains.txt')
url_11 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Lazarus/hashes.txt').text)
url11 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Lazarus/hashes.txt')
url_12 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Lazarus/ips.txt').text)
url12 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Lazarus/ips.txt')
url_13 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Confucius/domains.txt').text)
url13 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Confucius/domains.txt')
url_14 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Confucius/hashes.txt').text)
url14 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Confucius/hashes.txt')
url_15 = (get('https://raw.githubusercontent.com/Ebryx/IOCs/master/Confucius/ips.txt').text)
url15 = ('https://raw.githubusercontent.com/Ebryx/IOCs/master/Confucius/ips.txt')
url_16 = (get('https://urlhaus.abuse.ch/downloads/text/').text)
url16 = ('https://urlhaus.abuse.ch/downloads/text/')

repeat = 'y'
while repeat == 'y':
    
    IOC = input(colour.BOLD + colour.GREEN + '\nPlease provide an IOC: ' + colour.END)

    print(colour.YELLOW + colour.BOLD + "\n" + "Github IOC Repo Search:" + colour.END)
    if IOC == "":
        print("\n" + 'Please provide an IOC')
    elif IOC in url_1:
        print(colour.RED + "\n" + "IOC Detected in URL 1!")
        print(url1 + colour.END)
    elif IOC in url_2:
        print(colour.RED + "\n" + "IOC Detected in URL 2!")
        print(url2 + colour.END)
    elif IOC in url_3:
        print(colour.RED + "\n" + "IOC Detected in URL 3!")
        print(url3 + colour.END)
    elif IOC in url_4:
        print(colour.RED + "\n" + "IOC Detected in URL 4!")
        print(url4 + colour.END)
    elif IOC in url_5:
        print(colour.RED + "\n" + "IOC Detected in URL 5!")
        print(url5 + colour.END)
    elif IOC in url_6:
        print(colour.RED + "\n" + "IOC Detected in URL 6!")
        print(url6 + colour.END)
    elif IOC in url_7:
        print(colour.RED + "\n" + "IOC Detected in URL 7!")
        print(url7 + colour.END)
    elif IOC in url_8:
        print(colour.RED + "\n" + "IOC Detected in URL 8!")
        print(url8 + colour.END)
    elif IOC in url_9:
        print(colour.RED + "\n" + "IOCDetected in URL 9!")
        print(url9 + colour.END)
    elif IOC in url_10:
        print(colour.RED + "\n" + "IOC Detected in URL 10!")
        print(url10 + colour.END)
    elif IOC in url_11:
        print(colour.RED + "\n" + "IOC Detected in URL 11!")
        print(url11 + colour.END)
    elif IOC in url_12:
        print(colour.RED + "\n" + "IOC Detected in URL 12!")
        print(url12 + colour.END)
    elif IOC in url_13:
        print(colour.RED + "\n" + "IOC Detected in URL 13!")
        print(url13 + colour.END)
    elif IOC in url_14:
        print(colour.RED + "\n" + "IOC Detected in URL 14!")
        print(url14 + colour.END)
    elif IOC in url_15:
        print(colour.RED + "\n" + "IOC Detected in URL 15!")
        print(url15 + colour.END)
    elif IOC in url_16:
        print(colour.RED + "\n" + "IOC Detected in URL 16!")
        print(url16 + colour.END)
    else:
        print("\n" + 'IOC Not found in URL search.')

    ################################ IP Blacklist Checker ################################

    warnings.filterwarnings("ignore", category=DeprecationWarning)


    def content_test(url, IOC):
        try:
            request = urllib3.Request(url)
            opened_request = urllib3.build_opener().open(request)
            html_content = opened_request.read()
            retcode = opened_request.code

            matches = retcode == 200
            matches = matches and re.findall(IOC, html_content)

            return len(matches) == 0
        except:
            return False


    bls = ["b.barracudacentral.org", "bl.spamcop.net",
           "blacklist.woody.ch", "cbl.abuseat.org",
           "combined.abuse.ch", "combined.rbl.msrbl.net",
           "db.wpbl.info", "dnsbl.cyberlogic.net",
           "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch",
           "duinv.aupads.org", "dul.dnsbl.sorbs.net", "dul.ru",
           "dynip.rothen.com",
           "http.dnsbl.sorbs.net", "images.rbl.msrbl.net",
           "ips.backscatterer.org", "ix.dnsbl.manitu.net",
           "korea.services.net", "misc.dnsbl.sorbs.net",
           "noptr.spamrats.com", "ohps.dnsbl.net.au", "omrs.dnsbl.net.au",
           "osps.dnsbl.net.au", "osrs.dnsbl.net.au",
           "owfs.dnsbl.net.au", "pbl.spamhaus.org", "phishing.rbl.msrbl.net",
           "probes.dnsbl.net.au", "proxy.bl.gweep.ca", "rbl.interserver.net",
           "rdts.dnsbl.net.au", "relays.bl.gweep.ca", "relays.nether.net",
           "residential.block.transip.nl", "ricn.dnsbl.net.au",
           "rmst.dnsbl.net.au", "smtp.dnsbl.sorbs.net",
           "socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.sorbs.net",
           "spam.rbl.msrbl.net", "spam.spamrats.com", "spamrbl.imp.ch",
           "t3direct.dnsbl.net.au", "tor.dnsbl.sectoor.de",
           "torserver.tor.dnsbl.sectoor.de", "ubl.lashback.com",
           "ubl.unsubscore.com", "virus.rbl.jp", "virus.rbl.msrbl.net",
           "web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org",
           "zen.spamhaus.org", "zombie.dnsbl.sorbs.net"]

    URLS = [
        # TOR
        ('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',
         'is not a TOR Exit Node',
         'is a TOR Exit Node',
         False),

        # EmergingThreats
        ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
         'is not listed on EmergingThreats',
         'is listed on EmergingThreats',
         True),

        # AlienVault
        ('http://reputation.alienvault.com/reputation.data',
         'is not listed on AlienVault',
         'is listed on AlienVault',
         True),

        # BlocklistDE
        ('http://www.blocklist.de/lists/bruteforcelogin.txt',
         'is not listed on BlocklistDE',
         'is listed on BlocklistDE',
         True),

        # Dragon Research Group - SSH
        ('http://dragonresearchgroup.org/insight/sshpwauth.txt',
         'is not listed on Dragon Research Group - SSH',
         'is listed on Dragon Research Group - SSH',
         True),

        # Dragon Research Group - VNC
        ('http://dragonresearchgroup.org/insight/vncprobe.txt',
         'is not listed on Dragon Research Group - VNC',
         'is listed on Dragon Research Group - VNC',
         True),

        # NoThinkMalware
        ('http://www.nothink.org/blacklist/blacklist_malware_http.txt',
         'is not listed on NoThink Malware',
         'is listed on NoThink Malware',
         True),

        # NoThinkSSH
        ('http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
         'is not listed on NoThink SSH',
         'is listed on NoThink SSH',
         True),

        # Feodo
        ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
         'is not listed on Feodo',
         'is listed on Feodo',
         True),

        # antispam.imp.ch
        ('http://antispam.imp.ch/spamlist',
         'is not listed on antispam.imp.ch',
         'is listed on antispam.imp.ch',
         True),

        # dshield
        ('http://www.dshield.org/ipsascii.html?limit=10000',
         'is not listed on dshield',
         'is listed on dshield',
         True),

        # malc0de
        ('http://malc0de.com/bl/IP_Blacklist.txt',
         'is not listed on malc0de',
         'is listed on malc0de',
         True),

        # MalWareBytes
        ('http://hosts-file.net/rss.asp',
         'is not listed on MalWareBytes',
         'is listed on MalWareBytes',
         True)]

    if __name__ == "__main__":
            parser = argparse.ArgumentParser(description='Is This IP Bad?')
            parser.add_argument('-i', '--ip', help='IP address to check')
            parser.add_argument('--success', help='Also display GOOD', required=False, action="store_true")
            args = parser.parse_args()

            if args is not None and args.ip is not None and len(args.ip) > 0:
                IOC = args.ip
            else:
                my_ip = get('https://api.ipify.org').text
                print(colour.YELLOW + colour.BOLD + "\n" + "IP Blacklist Check" + colour.END)

            # IP INFO
            reversed_dns = socket.getfqdn(IOC)
            geoip = get('http://api.hackertarget.com/geoip/?q='
                        + IOC).text

            print('\nThe FQDN for {0} is {1}\n'.format(IOC, reversed_dns))
            print('Geolocation IP Information:')
            print(geoip)
            print('\n')

            BAD = 0
            GOOD = 0

            for url, succ, fail, mal in URLS:
                if content_test(url, IOC):
                    if args.success:
                        ('{0} {1}'.format(IOC, succ))
                        GOOD = GOOD + 1
                    else:
                        ('{0} {1}'.format(IOC, fail))
                        BAD = BAD + 1
            time.sleep(5)

            BAD = BAD
            GOOD = GOOD

            for bl in bls:
                try:
                    my_resolver = dns.resolver.Resolver()
                    query = '.'.join(reversed(str(IOC).split("."))) + "." + bl
                    my_resolver.timeout = 5
                    my_resolver.lifetime = 5
                    answers = my_resolver.query(query, "A")
                    answer_txt = my_resolver.query(query, "TXT")
                    print((IOC + ' is listed in ' + bl)
                          + ' (%s: %s)' % (answers[0], answer_txt[0]))
                    BAD = BAD + 1

                except dns.resolver.NXDOMAIN:
                    print(IOC + ' is not listed in ' + bl)
                    GOOD = GOOD + 1

                except dns.resolver.Timeout:
                    print('WARNING: Timeout querying ' + bl)

                except dns.resolver.NoNameservers:
                    print('WARNING: No nameservers for ' + bl)

                except dns.resolver.NoAnswer:
                    print('WARNING: No answer for ' + bl)

            print('\n{0} is on {1}/{2} blacklists.\n'.format(IOC, BAD, (GOOD + BAD)))

            print('Waiting 5 seconds before continuing..')
            time.sleep(5)

    ################################ IP Blacklist Checker ################################

    ################################ AbuseIPDB API Search - https://www.abuseipdb.com/ ################################

    print(colour.BOLD + colour.YELLOW + "\nAbuseIPDB Results: (https://www.abuseipdb.com/)\n" + colour.END)

    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': IOC,
        'maxAgeInDays': '365'
    }

    headers = {
        'Accept': 'application/json',
        'Key': '6e550f5902dd974b8a041786ca828c52c7fa079c08eb5c2bc4af5a8574a63b75f5eb4da2d1795b0f'
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))

    print("Result: https://www.abuseipdb.com/check/" + IOC)

    ################################ AbuseIPDB API Search - https://www.abuseipdb.com/ ################################

    ################################ OPSWAT API Search - https://metadefender.opswat.com/?lang=en ################################

    print(colour.BOLD + colour.YELLOW + "\nOPSWAT Results: (https://metadefender.opswat.com/?lang=en)\n" + colour.END)

    url = "https://api.metadefender.com/v4/ip/" + IOC

    headers = {
        'apikey': "304d6fe8f5077c722fea50c0f0e5e3f4"
    }

    response = requests.request("GET", url, headers=headers)

    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))

    ################################ OPSWAT API Search - https://metadefender.opswat.com/?lang=en ################################

    ################################ URLScan API Search - https://urlscan.io/ ################################

    print(colour.BOLD + colour.YELLOW + "\nURLScan Results: (https://urlscan.io/)\n" + colour.END)

    headers = {'API-Key': '3887381d-1541-4bfd-9708-e9a3d1756fd4', 'Content-Type': 'application/json'}
    data = {"url": IOC, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))

    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))

    ################################ URLScan API Search - https://urlscan.io/ ################################

    ################################ FraudGuard API Search - https://app.fraudguard.io/ ################################

    print(colour.BOLD + colour.YELLOW + "\nFraudGuard Results: (https://app.fraudguard.io/)\n" + colour.END)

    ip = requests.get('https://api.fraudguard.io/v2/ip/' + IOC, verify=True,
                      auth=HTTPBasicAuth('6xocMVSaRZa2d4p0', 'KtbU72FmmNsQChVw'))
    decodedResponse = json.loads(ip.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))

    print("Result: https://fraudguard.io/?ip=" + IOC)

    ################################ FraudGuard API Search - https://app.fraudguard.io/ ################################

    print(colour.BOLD + colour.BLUE + '\nQuicklinks:' + colour.END)
    print(colour.CYAN + 'https://www.abuseipdb.com/check/' + IOC)
    print('https://www.virustotal.com/gui/search/' + IOC)
    print('https://exchange.xforce.ibmcloud.com/search/' + IOC)
    print('https://talosintelligence.com/reputation_center/lookup?search=' + IOC + colour.END) 

    yn = input(colour.BOLD + colour.GREEN + '\nWould you like to check another IOC? (y/n): ' + colour.END)
    if yn == "y":
        continue
    else:
        break
