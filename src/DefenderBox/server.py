#!/usr/bin/env/ python3

# Adedotun Odutola aco0008
# Auburn University Capstone Project
# server.py

import socket 
import grpc
from concurrent import futures
import time

# import the generated classes
import defend_pb2_grpc
import defend_pb2

# import the defend file
import defend

SERVER_ADDRESS = 'localhost:23350'


# create a class to define the server functions, derived 
class DefendServicer(defend_pb2_grpc.DefendServicer):
    
    def MonitorConfigurationFile(self, request, context):
        response = defend_pb2.CheckConfigFileStatusResponse()
        response.ipAttacking = defend.monitorConfigDir(request.pathToConfigFile)
        return response
        
    def UpdateNetworkConfiguration(self, request, context):
        response = defend_pb2.UpdateNetworkConfigurationResponse()
        
        attackerIp = request.ip
        openPorts = request.port
        TURN_ON_FIREWALL = request.turnOnFirewall
        TURN_ON_FIREWALL_LOGGING = request.turnOnFirewallLogging
        CLOSE_PORT = request.closePort
        
        if attackerIp != "":
            response.blockIpResponse = defend.attemptBlockIp(attackerIp)
        if CLOSE_PORT == True:
                response.closePortResponse = defend.closeOpenPorts(openPorts)
        if TURN_ON_FIREWALL == True:
            response.updateFireWallResponse = defend.turnOnFirewall()
            time.sleep(5)
        if TURN_ON_FIREWALL_LOGGING == True:
            response.updateFireWallLoggingResponse = defend.turnOnFirewallLogging()
  	   
        return response

    def IdentifySystemVulnerabilities(self, request, context):
        response = defend_pb2.FindSystemVulnerabilitiesResponse()
        if(request.checkForOpenPorts == True):
            openPorts = defend.scanForOpenPorts()
            response.port.extend(openPorts)
        if(request.checkFireWall == True):
            response.fireWallOff = defend.checkFirewall()
        if(request.checkFireWallLogging == True):
            response.fireWallLoggingOff = defend.checkFirewallLogging()
            
        return response
            
    def FindAttackerPresence(self, request, context):
        response = defend_pb2.FindAttackerPresenceResponse()
        if(request.malwareScan == True):
            response.malwareScan = defend.malwareScanSystem()
        if(request.scanNetworkActivity == True):
            response.networkActivityScanResponse = defend.scanNetworkTraffic()
        if(request.checkLogs == True):
            response.logResponse = defend.scanLogs()
        return response

def main():
    # create a gRPC server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    defend_pb2_grpc.add_DefendServicer_to_server(
        DefendServicer(), server)


    print('Waiting for Client...')
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
