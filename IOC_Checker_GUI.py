print('\n')
print("##      ##      ##      ##       #######  ")
print("####    ##      ###    ###      ##     ## ")
print("## ##   ##      ## #### ##      ##        ")
print("##  ##  ##      ##  ##  ##      ##        ")
print("##   ## ##      ##      ##      ##        ")
print("##     ###      ##      ##      ##     ## ")
print("##      ##      ##      ##       #######  ")
print('\n')

# Current Issues:
# Have to click twice on "Quicklinks "Ok" and Links to activate
# Quicklinks only opens https://google.com, need to figure out how to allow each link to open seperately
# Remove colour from IP Blacklist Check (FQDN, Geolocation IP Information, Blacklists)

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
try:
    import PySimpleGUI as sg
except ImportError:
    print('Trying to install required module - PySimpleGui \n')
    os.system('python -m pip install PySimpleGui')
from tkinter import Tk
from dns import resolver
from requests.auth import HTTPBasicAuth
from requests import get

sg.theme('LightGrey3') #Sets GUI colour

print('Version | 1.0 |')
print('Author  | Kieran Harper |')

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
    
    ################################ Prompt for IOC ################################

    # Define the window's contents
    layout = [[sg.Text("Please provide the IP/Domain/URL you wish to search for:")],  # Part 2 - The Layout
              [sg.InputText()],
              [sg.Button('Submit')]]

    # Create the window
    window = sg.Window('IOC Checker', layout)  # Part 3 - Window Defintion

    # Display and interact with the Window
    event, values = window.read()  # Part 4 - Event loop or Window.read call

    # Do something with the information gathered
    IOC = values[0]

    # Finish up by removing from the screen
    window.close()  # Part 5 - Close the Window

    ################################ Prompt for IOC ################################

    print('\n' + IOC)
    print("\n" + "Github IOC Repo Search:")
    if IOC == "":
        print("\n" + 'Please provide an IOC')
    elif IOC in url_1:
        print("\n" + "IOC Detected in URL 1!")
        print(url1)
    elif IOC in url_2:
        print("\n" + "IOC Detected in URL 2!")
        print(url2)
    elif IOC in url_3:
        print("\n" + "IOC Detected in URL 3!")
        print(url3)
    elif IOC in url_4:
        print("\n" + "IOC Detected in URL 4!")
        print(url4)
    elif IOC in url_5:
        print("\n" + "IOC Detected in URL 5!")
        print(url5)
    elif IOC in url_6:
        print("\n" + "IOC Detected in URL 6!")
        print(url6)
    elif IOC in url_7:
        print("\n" + "IOC Detected in URL 7!")
        print(url7)
    elif IOC in url_8:
        print("\n" + "IOC Detected in URL 8!")
        print(url8)
    elif IOC in url_9:
        print("\n" + "IOCDetected in URL 9!")
        print(url9)
    elif IOC in url_10:
        print("\n" + "IOC Detected in URL 10!")
        print(url10)
    elif IOC in url_11:
        print("\n" + "IOC Detected in URL 11!")
        print(url11)
    elif IOC in url_12:
        print("\n" + "IOC Detected in URL 12!")
        print(url12)
    elif IOC in url_13:
        print("\n" + "IOC Detected in URL 13!")
        print(url13)
    elif IOC in url_14:
        print("\n" + "IOC Detected in URL 14!")
        print(url14)
    elif IOC in url_15:
        print("\n" + "IOC Detected in URL 15!")
        print(url15)
    elif IOC in url_16:
        print("\n" + "IOC Detected in URL 16!")
        print(url16)
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
                print("\n" + "IP Blacklist Check")

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

    print("\nAbuseIPDB Results: (https://www.abuseipdb.com/)\n")

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

    print("\nOPSWAT Results: (https://metadefender.opswat.com/?lang=en)\n")

    url = "https://api.metadefender.com/v4/ip/" + IOC

    headers = {
        'apikey': "304d6fe8f5077c722fea50c0f0e5e3f4"
    }

    response = requests.request("GET", url, headers=headers)

    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))

    ################################ OPSWAT API Search - https://metadefender.opswat.com/?lang=en ################################

    ################################ URLScan API Search - https://urlscan.io/ ################################

    print("\nURLScan Results: (https://urlscan.io/)\n")

    headers = {'API-Key': '3887381d-1541-4bfd-9708-e9a3d1756fd4', 'Content-Type': 'application/json'}
    data = {"url": IOC, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))

    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))

    ################################ URLScan API Search - https://urlscan.io/ ################################

    ################################ Links ################################

    # Define the window's contents
    layout = [[sg.Text("Quicklinks: " +
                        "\n https://www.abuseipdb.com/check/" + IOC +
                        "\n https://virustotal.com/gui/search/" + IOC +
                        "\n https://exchange.xforce.ibmcloud.com/search/" + IOC +
                        "\n https://talosintelligence.com/reputation_center/lookup?search=" + IOC +
                        "\n https://fraudguard.io/?ip=" + IOC +
                        "\n https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/" + IOC + ' (IP)'
                        "\n https://www.ipqualityscore.com/domain-reputation/" + IOC + ' (Domain) \n',

                       enable_events=True, key='-LINK-')],  # Part 2 - The Layout
              [sg.Button('Ok')]]

    # Create the window
    window = sg.Window('IOC Checker', layout)  # Part 3 - Window Defintion

    # Display and interact with the Window
    event, values = window.read()  # Part 4 - Event loop or Window.read call

    while True:  # Event Loop
        event, values = window.read()
        if event in (None, 'Exit'):
            break
        elif event == 'Ok':
            window.close()
        elif event == '-LINK-':
            webbrowser.open('https://www.google.com')

    ################################ Links ################################

    ################################ Prompt for Browser Open ################################

    # Define the window's contents
    layout = [[sg.Text("Do you want to open the first 4 results via your webrowser?"
               '\n \n https://www.abuseipdb.com/check/' + IOC +
               '\n https://virustotal.com/gui/search/' + IOC +
               '\n https://exchange.xforce.ibmcloud.com/search/' + IOC +
               '\n https://talosintelligence.com/reputation_center/lookup?search=' + IOC + '\n'
                       )],  # Part 2 - The Layout
              [sg.Button('Yes'), sg.Button('No')]]

    # Create the window
    window = sg.Window('IOC Checker', layout)  # Part 3 - Window Defintion

    # Display and interact with the Window
    event, values = window.read()  # Part 4 - Event loop or Window.read call

    # Do something with the information gathered
    browser_open = event

    # Finish up by removing from the screen
    window.close()  # Part 5 - Close the Window

    ################################ Prompt for Browser Open ################################

    if browser_open == 'Yes':
        webbrowser.open('https://www.abuseipdb.com/check/' + IOC)
        webbrowser.open('https://virustotal.com/gui/search/' + IOC)
        webbrowser.open('https://exchange.xforce.ibmcloud.com/search/' + IOC)
        webbrowser.open('https://talosintelligence.com/reputation_center/lookup?search=' + IOC)

    ################################ Prompt for check another IOC ################################

    # Define the window's contents
    layout = [[sg.Text("Do you want to check for another IOC?")],  # Part 2 - The Layout
              [sg.Button('Yes'), sg.Button('No')]]

    # Create the window
    window = sg.Window('IOC Checker', layout)  # Part 3 - Window Defintion

    # Display and interact with the Window
    event, values = window.read()  # Part 4 - Event loop or Window.read call

    # Do something with the information gathered
    yn = event

    # Finish up by removing from the screen
    window.close()  # Part 5 - Close the Window

    ################################ Prompt for check another IOC ################################

    if yn == "Yes":
        continue
    else:
        break
