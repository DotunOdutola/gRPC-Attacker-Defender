# Adedotun Odutola aco0008
# Auburn University Capstone Project
# defend.py

import os.path
import time
import os
import hashlib
import sys, glob, subprocess

homedir = os.path.expanduser('~')

# Function to monitor whether a specified configuration file "path" is altered
# Input: path to file
# Output: the attacking IP
def monitorConfigDir(path):
    fileNotChanged = True
    
    while not os.path.isfile(path):
        print("No Alert File Detected")
        time.sleep(10)
    
    prevModDate = os.stat(path)[8]

    while fileNotChanged == True:
        time.sleep(5)
        currentModDate = os.stat(path)[8]

        if prevModDate != currentModDate:

            fileNotChanged = False

    attacker = getAttacker(path)
    return attacker

# Function to grab the attacker IP after the system is alerted of an attack
# Input: path to configuration file
# Output: Attacker Ip
def getAttacker(path):

    fileDir = os.path.dirname(os.path.realpath(path))
    modified_folder_path = max(glob.glob(os.path.join(fileDir, '*/')), key=os.path.getmtime)
    
    attackingIp =  os.path.basename(os.path.normpath(modified_folder_path))
    
    return attackingIp


# Function to block an ip that it is given using Ubuntu's UFW firewall
# Input: IP to block
# Output: process response of the attempted block command
# Future use: pass in the port value that the attacker is attacking 
def attemptBlockIp(ip):
    port = 21
    process = subprocess.run(['ufw', 'insert', '1','deny', 'from', 
    		ip, 'to', 'any', 'port', '21'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
    return process.stdout

# Function to scan the system for open ports to ensure system is not vulnerable.
# Input: None
# Output: list of open ports found
# Future use: call on netstat using the subprocess call and parse the results to
# only return the port numbers that are open and return them. 
def scanForOpenPorts():
    process = subprocess.run(["netstat", "-ant"], check=True, stdout=subprocess.PIPE, universal_newlines=True)
    output = process.stdout
    openPorts = []
    return openPorts

# Unimplemented because portsOpen would never be populated. See above
# Function to close open ports found in the scanForOpenPorts() function.
# Input: list of open ports 
# Output: stdout of the subprocess command.
# Future Use: allow for the use to close open ports or open closed ports depending
# on the boolean value passed in.
def closeOpenPorts(ports):
    try:
        for port in ports:
            process = subprocess.run(['ufw', 'allow', port], check=True, stdout=subprocess.PIPE, universal_newlines=True)
            if process.returncode == 0:
                print(process.stdout)
            else:
    	        print("Error Closing Port: " + port)
        return "Ports Closed"
    except:

        print("UFW Command Error")
        return "Firewall Off"       

# Function to check whether or not the firewall is active 
# Input: None
# Output: Firewall Status string
def checkFirewall():
    FIREWALL_OFF = None
    try:
        process = subprocess.run(['ufw', 'status'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
        if process.returncode == 0:
            output = process.stdout.split()
            if 'inactive' in output:
                FIREWALL_OFF = True
                print("Firewall off")
            else:
            	print('Firewall active')
            	FIREWALL_OFF = False
                
                
    except:
        print("UFW Command Error")
    return FIREWALL_OFF

# Function to turn on firewall 
# Input: None
# Output: Firewall Status string
def turnOnFirewall():
    try:
        process = subprocess.run(['ufw', 'enable'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
        if process.returncode == 0:
            return process.stdout   
        else:
    	    return "Error Turning On Firewall"
    except:

        print("UFW Command Error")
        return "Firewall Off"

# Function to turn on firewall logging
# Input: None
# Output: Firewall Logging Status string
def turnOnFirewallLogging():
    try:
        process = subprocess.run(['ufw', 'logging', 'on'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
        if process.returncode == 0:
            return process.stdout  
        else:
    	    return "Error Turning On Firewall Logging"    
    except:

        print("UFW Command Error")
        return "Firewall Logging Off"

# Function to check whether or not the firewall logging is on 
# Input: None
# Output: Firewall logging Status string
def checkFirewallLogging():
    FIREWALL_LOGGING_OFF = None
    try:
        process = subprocess.run(['ufw', 'status', 'verbose'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
        if process.returncode == 0:
            output = process.stdout.split()
            if 'Logging:' in output and 'on' in output:
                print(process.stdout)
                FIREWALL_LOGGING_OFF = False
                 
            else:
                FIREWALL_LOGGING_OFF = True 
                return FIREWALL_LOGGING_OFF 
    except:
        print("UFW Command Error")
        FIREWALL_LOGGING_OFF = True
    return FIREWALL_LOGGING_OFF

# Function to scan for malware/backdoors that an attacker
# may of left on the system
# Input: None
# Output: Stdout from the scan initiated. (i.e., ossec, etc.)
# Future use: This function will trigger a scan from a tool or manual command
# and return the results of the scan. Another function would need to be created
# to handle the results. (i.e., remove the malware)
def malwareScanSystem():
    return "Scan Tool Disabled"
    
# Function to scan network traffic that an attacker may be initiating on 
# the network
# Input: None
# Output: Stdout response from the scan.
# Future use: This function will trigger a scan of network activity that is
# involving this system. (i.e., netstat)   
def scanNetworkTraffic():
    return "Scan Disabled"

# Function to search through logs for things that have been altered.
# Opens the specified file and parses through it searching for 
# certain key words to trigger something has been altered and 
# if found deletes it.
# Input: None (future use: could include locations of directories to scan)
# Output: Stdout from the search initiated. 
# Future use: This function can be parsed however the user needs it to be.
# This function can be passed the path of file(s) to monitor. 
def scanLogs():
    path = '/var/log/auth.log'   
    contents = ''
    fsize = os.stat(path).st_size
    with open(path,'r') as f:
        contents = f.read()
    if 'useradd' in contents:
        contents = contents.split()
        newUser = contents[contents.index('group') + 1]
        newUser = newUser.strip("''")
        print('A new user ' + newUser + ' was created..')
        # Attempt to remove the user
        try:
            process = subprocess.run(['deluser', newUser], check=True, stdout=subprocess.PIPE, universal_newlines=True)
            if process.returncode == 0:
            	output = process.stdout
            	response = 'A new user was created. Deleting..\n' + output
            	return response   
        except:
            response = 'New user: ' + newUser + ' created. Was unable to delete'
            return response      
    else:
        response = 'No user added.'
        return response

