#!/usr/bin/env/ python3

# Adedotun Odutola aco0008
# Auburn University Capstone Project
# server.py

import socket 
import grpc
from concurrent import futures
import time

# import the generated classes
import attack_pb2_grpc
import attack_pb2

# import the attack file
import attack

SERVER_ADDRESS = 'localhost:23229'

# create a class to define the server functions, derived 
class AttackServicer(attack_pb2_grpc.AttackServicer):
    
    def FindAMachine(self, request, context):
        response = attack_pb2.MachinesUpResponse()
        response.machines.extend(attack.hostScan(request.subnetMasks))
        return response
    
    def FingerPrint(self, request, context):
        response = attack_pb2.FingerPrintResponse()
        portList = request.portsToScan
        openPorts = attack.portScan(portList, request.activeMachine)
        response.port.extend(openPorts)
        return response

    def GainAccess(self, request, context):
        response = attack_pb2.GainAccessResponse()
        response.gainedAccess, response.user, response.password, response.accessMethod = attack.gainAccess(request.machineInformation, request.targetHost)
        return response

    def AddBackdoor(self, request, context):
        response = attack_pb2.AddBackdoorResponse()
        response.backdoorCommandResponse = attack.addBackdoor(request.backdoorCommand, request.user, request.password, request.host)
        return response        
        
    def TriggerAttack(self, request, context):
        response = attack_pb2.TriggerAttackResponse()
        response.attackResponse = attack.initiateAttack(request.attackCommand, request.user, request.password, request.host)
        return response  
    
    def ClearTracks(self, request, context):
        response = attack_pb2.ClearTracksResponse()
        if(request.removeLogs == False):
            return response
        else:         
            return response      

def main():
    # create a gRPC server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    attack_pb2_grpc.add_AttackServicer_to_server(
        AttackServicer(), server)

    # listen on port 50051
    print('Waiting for client...')
    server.add_insecure_port(SERVER_ADDRESS)
    server.start()  
      
    # since server.start() will not block,
    # a sleep-loop is added to keep alive
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    main()
