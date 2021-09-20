import sys
import socket
from datetime import datetime

#Syntax to run is 'python3 [FileName] [Target]'

#Define target
if len(sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1]) #Translate hostname to IPV4
else:
    print('Invalid amount of arguments.')
    print('Syntax: python3 port_scanner.py [IP]')

#Banner
print('-' * 50)
print('Scanning target ' + target)
print('Scan started at ' +str(datetime.now()))
print('-' * 50)

try:
        for port in range(0,100): #Port scan range
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Setting 'S' variable
            socket.setdefaulttimeout(1) #Default timeout set to 1 second
            result = s.connect_ex((target,port)) #Returns error indicator
            if result == 0:
                print('Port {} is open'.format(port))
            s.close()

except KeyboardInterrupt:
        print('Exiting program.')
        sys.exit()

except socket.gaierror:
        print('Hostname could not be resolved.')

except socket.error:
        print("Couldn't connect to server.")