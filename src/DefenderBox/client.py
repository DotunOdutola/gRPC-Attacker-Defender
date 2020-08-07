# Adedotun Odutola aco0008
# Auburn University Capstone Project
# client.py

import socket 
import grpc
import os.path
import defend_pb2_grpc
import defend_pb2
import time

SERVER_ADDRESS = "localhost:23350"
# Path to the config file we want to monitor
filePath = '/var/log/snort/snort.log'

# Function to identify vulnerabilities in system.
# Input: client stub
# Output: None
def checkSystemForVulnerabilities(stub):
    # Define checks that you want to perform
    turnOnFirewall = ""
    turnOnFirewallLogging = ""
    closeOpenPorts = True
    
    print("Identifying system for vulnerabilities")
    
    # create a valid request message
    request = defend_pb2.FindSystemVulnerabilitiesRequest(checkForOpenPorts=False, 
                                            checkFireWall = True,
                                            checkFireWallLogging=True,
                                            checkToolRunning=False)
    # make the call
    response = stub.IdentifySystemVulnerabilities(request)
    portsOpen = False
    ports = response.openPorts
    if not ports:
        portsOpen = False
    else:
        portsOpen = True
        
    if(response.fireWallOff == True):
        turnOnFirewall = True
        print("Firewall is Off")
    else:
        turnOnFirewall = False
        print("Firewall is Active")
        
    if(response.fireWallLoggingOff==True):
        turnOnFirewallLogging = True
        print("Found: Firewall Logging is Off")
    else:
        turnOnFirewallLogging = False
        print("Firewall Logging is On.")

    updateNetworkConfig(stub, openPorts=ports, closePorts=closeOpenPorts, turnOnFirewall=turnOnFirewall,turnOnFireWallLogging=turnOnFirewallLogging)    

# Function to monitor specific configuration file
# Input: client stub
# Output: string containing attacking IP
# Note: This function will stay in a loop until an attack is attempted
def checkConfigFile(stub):
    print('Monitoring config file...')
    # create a valid request message
    request = defend_pb2.CheckConfigFileStatusRequest(pathToConfigFile=filePath)
    # make the call
    configFileStatusResponse = stub.MonitorConfigurationFile(request)
    print('Being attacked from ip: ' + configFileStatusResponse.ipAttacking)   
    updateNetworkConfig(stub, configFileStatusResponse.ipAttacking)
    return configFileStatusResponse.ipAttacking

# Function to update network configuration settings
# Required Input: client stub
# Optional Input: string - attacking ip, list - openPorts, Boolean - closePorts
#                    Boolean - turnOnFirewall, Boolean - turnOnFirewallLogging
# Output: None
def updateNetworkConfig(stub, attackingIp=None, openPorts=None, closePorts = None, turnOnFirewall = None, turnOnFireWallLogging = None):
    
    if attackingIp != None:
        # create a valid request message
        request = defend_pb2.UpdateNetworkConfigurationRequest(ip=attackingIp)
        # make the call	
        response = stub.UpdateNetworkConfiguration(request)
        print('Blocking attacking IP: ' + attackingIp)
    else:
        pass
    
    if not openPorts:
        if closePorts == True:
            # close the open ports
            request = defend_pb2.UpdateNetworkConfigurationRequest(port=openPorts,
            closePort=closePorts)
            # make the call
            response = stub.UpdateNetworkConfiguration(request)
            print(response.closePortResponse)
    if turnOnFirewall != None:
        if turnOnFirewall == True:
            # Turn on Firewall
            request = defend_pb2.UpdateNetworkConfigurationRequest(turnOnFirewall=turnOnFirewall)
            # make the call
            response = stub.UpdateNetworkConfiguration(request)
            print(response.updateFireWallResponse)            
    
    if turnOnFireWallLogging != None:
        if turnOnFireWallLogging == True:
            # Turn on Firewall
            request = defend_pb2.UpdateNetworkConfigurationRequest(turnOnFirewallLogging=turnOnFireWallLogging)
            # make the call
            response = stub.UpdateNetworkConfiguration(request)
            print(response.updateFireWallLoggingResponse)    

# Function to search machine for attacker presence.
# Input: client stub
# Output: None    
# Notes: For the purpose of testing, added a 45 second sleep period to allot for attacker.           
def findAttackerOnSystem(stub):
    time.sleep(45)
    print('Scanning through logs for unusual activity...')
    # create a valid request message
    request = defend_pb2.FindAttackerPresenceRequest(malwareScan=False,scanNetworkActivity=False,checkLogs=True)
    # make the call
    response = stub.FindAttackerPresence(request)
    print(response.logResponse)

# Main function initiating calls
def main():
    # open a gRPC channel
    with grpc.insecure_channel(SERVER_ADDRESS) as channel:
        
        # create a stub (client)
        stub = defend_pb2_grpc.DefendStub(channel)
        checkSystemForVulnerabilities(stub)
        ipAttacking = checkConfigFile(stub) 
        findAttackerOnSystem(stub)
        
if __name__ == '__main__':
    main()
