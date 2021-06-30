print('\n')
print("##      ##      ##      ##       #######  ")
print("####    ##      ###    ###      ##     ## ")
print("## ##   ##      ## #### ##      ##        ")
print("##  ##  ##      ##  ##  ##      ##        ")
print("##   ## ##      ##      ##      ##        ")
print("##     ###      ##      ##      ##     ## ")
print("##      ##      ##      ##       #######  ")
print('\n')
print('Version | 2.0 |')
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
try:
    import PySimpleGUI as sg
except ImportError:
    print('Trying to install required module - PySimpleGui \n')
    os.system('python -m pip install PySimpleGui')
from tkinter import Tk
from dns import resolver
from requests.auth import HTTPBasicAuth
from requests import get

sg.theme('LightGrey2') #Sets GUI colour

repeat = 'y'
while repeat == 'y':

    ################################ Prompt for IOC ################################

    # Define the window's contents
    layout = [[sg.Text("Please provide the IP/File Hash you wish to check:")],  # Part 2 - The Layout
              [sg.InputText()],
              [sg.Button('Submit'), sg.Button('Cancel')]]

    # Create the window
    window = sg.Window('IOC Checker', layout)  # Part 3 - Window Defintion

    # Display and interact with the Window
    event, values = window.read()  # Part 4 - Event loop or Window.read call

    # Do something with the information gathered
    IOC = values[0]
    Cancel = event

    # Finish up by removing from the screen
    window.close()  # Part 5 - Close the Window

    if Cancel == 'Cancel':
        break

    ################################ Prompt for IOC ################################

    ################################ VirusTotal FileHash Check ################################

    requests.urllib3.disable_warnings()
    client = requests.session()
    client.verify = False

    apikey = ('c45a24170dcd2464e11e66f638fd57f59b9de84495778cf26f6001595260fe14')

    try:
        def get_hash_report(apikey, filehash):
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {"apikey": apikey, "resource": filehash, "allinfo": True}

            r = client.get(url, params=params)

            if r.status_code == 429:
                print('Encountered rate-limiting. Sleeping for 45 seconds.')
                time.sleep(45)
                get_hash_report(apikey, filehash)

            elif r.status_code != 200:
                print('Encountered rate-limiting. Sleeping for 60 seconds.')
                print(r.status_code)
                time.sleep(60)  # Will sleep for 60 seconds, to allow the API limit (4 per min) to reset
                get_hash_report(apikey, filehash)

            elif r.status_code == 200:
                response = r.json()
                parse_hash_report(response)

        def parse_hash_report(response):
            detections = response['positives']
            if detections >= 1:
                scan_results = response['scans']

                print('\n---- File Hash Check ----')
                print("\nVirusTotal Results: https://www.virustotal.com/gui/home/upload")
                print('\nAV Name, Malware Name:\n')
                for vendor in scan_results:
                    if scan_results[vendor]['detected']:
                        info_date = scan_results[vendor]['update']
                        detected_name = scan_results[vendor]['result']
                        definition_version = scan_results[vendor]['version']

                        print('{!s}, {!s}'.format(vendor, detected_name))
            else:
                print('\nNo malicious detections found.')

        if True:
            filehash = IOC
            get_hash_report(apikey, filehash)

    ################################ VirusTotal FileHash Check ################################

    ################################ OPSWAT File Hash Check - https://metadefender.opswat.com/?lang=en ################################

        print("\nOPSWAT Results: https://metadefender.opswat.com/?lang=en" + "\n")

        url = "https://api.metadefender.com/v4/hash/" + IOC

        headers = {
            'apikey': "304d6fe8f5077c722fea50c0f0e5e3f4"
        }

        response = requests.request("GET", url, headers=headers)

        decodedResponse = json.loads(response.text)

    ################################ OPSWAT File Hash Check - https://metadefender.opswat.com/?lang=en ################################

    ################################ JSON Parse ################################

        f = decodedResponse
        try:
            print("File Size: ", f["file_info"]["file_size"], 'KB ' + '(OPSWAT)')
        except:
            print('File Size: N/A (OPSWAT)')
        try:
            print("File Type:", f["file_info"]["file_type_extension"], '(OPSWAT)')
        except:
            print('File Type: N/A (OPSWAT)')
        try:
            print("Malware family:", f["malware_family"], '(OPSWAT)')
        except:
            print('Mlaware family: N/A (OPSWAT)')
        try:
            print("Malware Type:", f["malware_type"][0], '(OPSWAT)')
            print("Malware Type:", f["malware_type"][1], '(OPSWAT)')
        except:
            print('Mlaware Type: N/A (OPSWAT)')
        try:
            print("AV Detections:", f["scan_results"]["total_detected_avs"], '(OPSWAT)')
        except:
            print('AV Detections: N/A (OPSWAT)')
        try:
            print("Threat Name:", f["threat_name"], '(OPSWAT)')
        except:
            print('Threat Name: N/A (OPSWAT)')

    except:
        print('')

        ################################ JSON Parse ################################

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

            reversed_dns = socket.getfqdn(IOC)
            geoip = get('http://api.hackertarget.com/geoip/?q='
                        + IOC).text

            print('\nThe FQDN for {0} is {1}\n'.format(IOC, reversed_dns))
            print('----- Geolocation IP Information ----- \n')
            print(geoip)
            print('\n----- Blacklist Check ------\n')

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
            #time.sleep(5)

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
                    IOC + ' is not listed in ' + bl
                    GOOD = GOOD + 1

                except dns.resolver.Timeout:
                    print('WARNING: Timeout querying ' + bl)

                except dns.resolver.NoNameservers:
                    print('WARNING: No nameservers for ' + bl)

                except dns.resolver.NoAnswer:
                    print('WARNING: No answer for ' + bl)

            print('\n{0} is on {1}/{2} blacklists.'.format(IOC, BAD, (GOOD + BAD)))

            #print('Waiting 5 seconds before continuing..')
            #time.sleep(1)

        ################################ IP Blacklist Checker ################################

        print('\n----- API Check ------\n')

        ################################ Virus Total search ################################

        #print("\nVirusTotal Results: https://www.virustotal.com/gui/ip-address/"+IOC+"/detection" + "\n")

        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

        params = {'apikey': 'c45a24170dcd2464e11e66f638fd57f59b9de84495778cf26f6001595260fe14', 'ip': IOC}

        response = requests.request(method='GET', url=url, params=params)

        decodedResponse = json.loads(response.text)

        f = decodedResponse
        try:
            print("Security Vendor Detections:",f["detected_urls"][0]["positives"],"out of 85",'(VirusTotal)')
        except:
            print('Security Vendor Detections: 0 out of 85 (VirusTotal)')

        ################################ Virus Total search ################################

        ################################ AbuseIPDB API Search - https://www.abuseipdb.com/ ################################

        #print("\nAbuseIPDB Results: https://www.abuseipdb.com/" + IOC + "\n")

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

        decodedResponse = json.loads(response.text)

        f = decodedResponse
        try:
            print("Abuse Confidence Score:",f["data"]["abuseConfidenceScore"], "% out of 100%","(AbusedIPDB)")
        except:
            print('Abuse Confidence Score: 0 (AbusedIPDB)')
        try:
            print("Total Reports:",f["data"]["totalReports"],"(AbusedIPDB)")
        except:
            print('Total Reports: 0 (AbusedIPDB)')

        ################################ AbuseIPDB API Search - https://www.abuseipdb.com/ ################################

        ################################ OPSWAT API Search - https://metadefender.opswat.com/?lang=en ################################

        ##print("\nOPSWAT Results: https://metadefender.opswat.com/?lang=en" + "\n")

        url = "https://api.metadefender.com/v4/ip/" + IOC

        headers = {
            'apikey': "304d6fe8f5077c722fea50c0f0e5e3f4"
        }

        response = requests.request("GET", url, headers=headers)

        decodedResponse = json.loads(response.text)

        f = decodedResponse
        try:
            print("Assessment:",f["lookup_results"]["sources"][0]["assessment"],'(OPSWAT)')
        except:
            print('Assessment: N/A (OPSWAT)')
        try:
            print("Engine Detections:", f["lookup_results"]["detected_by"],"out of 6",'(OPSWAT)')
        except:
            print('Engine Detections: 0 out of 6 (OPSWAT)')

        ################################ OPSWAT API Search - https://metadefender.opswat.com/?lang=en ################################

        ################################ GreyNoise API ################################

        #print("\nGreyNoise Results: https://viz.greynoise.io/query/?gnql=" + IOC + "\n")

        url = "https://api.greynoise.io/v3/community/" + IOC

        headers = {"Accept": "application/json"}

        response = requests.request("GET", url, headers=headers)

        decodedResponse = json.loads(response.text)

        f = decodedResponse
        try:
            print("Classification:", f["classification"],'(GreyNoise)')
        except:
            print('Classification: N/A (GreyNoise)')

        ################################ GreyNoise API ################################

        ################################ ThreatFox Check ################################

        url = 'https://threatfox-api.abuse.ch/api/v1/'
        payload = '{ "query": "search_ioc", "search_term": "139.180.203.104" }'  # Error with variable in payload
        headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
        response = requests.post(url, data=payload, headers=headers)
        decodedResponse = json.loads(response.text)

        f = decodedResponse

        try:
            print("Confidence Level:", f["data"][0]['confidence_level'], '(ThreatFox)')
        except:
            print('No result found (ThreatFox)')
        try:
            print("Malware:", f["data"][0]['malware'], '(ThreatFox)')
        except:
            print('No result found (ThreatFox)')
        try:
            print("Malware Alias:", f["data"][0]['malware_alias'], '(ThreatFox)')
        except:
            print('No result found (ThreatFox)')
        try:
            print("Malware type:", f["data"][0]['malware_printable'], '(ThreatFox)')
        except:
            print('No result found (ThreatFox)')
        try:
            print("Threat Type:", f["data"][0]['threat_type'], '(ThreatFox)')
        except:
            print('No result found (ThreatFox)')
        try:
            print("Threat Description:", f["data"][0]['threat_type_desc'], '(ThreatFox)')
        except:
            print('No result found (ThreatFox)')

        ################################ ThreatFox Check ################################

        ################################ Prompt for Browser Open ################################

        layout = [[sg.Text("Do you want to open the first 5 results via your webrowser?"
                   '\n \n https://www.abuseipdb.com/check/' + IOC +
                   '\n https://virustotal.com/gui/search/' + IOC +
                   '\n https://exchange.xforce.ibmcloud.com/search/' + IOC +
                   '\n https://talosintelligence.com/reputation_center/lookup?search=' + IOC +
                   '\n https://viz.greynoise.io/query/?gnql=' + IOC + '\n'
                           )],
                  [sg.Button('Yes'), sg.Button('No')]]

        window = sg.Window('IOC Checker', layout)

        event, values = window.read()

        browser_open = event

        window.close()

        ################################ Prompt for Browser Open ################################

        if browser_open == 'Yes':
            webbrowser.open('https://virustotal.com/gui/search/' + IOC)
            webbrowser.open('https://www.abuseipdb.com/check/' + IOC)
            webbrowser.open('https://exchange.xforce.ibmcloud.com/search/' + IOC)
            webbrowser.open('https://talosintelligence.com/reputation_center/lookup?search=' + IOC)
            webbrowser.open('https://viz.greynoise.io/query/?gnql=' + IOC)

    ################################ Prompt to check another IOC ################################

    layout = [[sg.Text("Do you want to check for another IOC?")],
                [sg.Button('Yes'), sg.Button('No')]]

    window = sg.Window('IOC Checker', layout)

    event, values = window.read()

    yn = event

    window.close()

    ################################ Prompt to check another IOC ################################

    if yn == "Yes":
        continue
    else:
        break
