# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import attack_pb2 as attack__pb2


class AttackStub(object):
    """Interface exported by the server
    a Attack service
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.FindAMachine = channel.unary_unary(
                '/Attack/FindAMachine',
                request_serializer=attack__pb2.FindAMachineRequest.SerializeToString,
                response_deserializer=attack__pb2.MachinesUpResponse.FromString,
                )
        self.FingerPrint = channel.unary_unary(
                '/Attack/FingerPrint',
                request_serializer=attack__pb2.FingerPrintMachineRequest.SerializeToString,
                response_deserializer=attack__pb2.FingerPrintResponse.FromString,
                )
        self.GainAccess = channel.unary_unary(
                '/Attack/GainAccess',
                request_serializer=attack__pb2.GainAccessRequest.SerializeToString,
                response_deserializer=attack__pb2.GainAccessResponse.FromString,
                )
        self.AddBackdoor = channel.unary_unary(
                '/Attack/AddBackdoor',
                request_serializer=attack__pb2.AddBackdoorRequest.SerializeToString,
                response_deserializer=attack__pb2.AddBackdoorResponse.FromString,
                )
        self.TriggerAttack = channel.unary_unary(
                '/Attack/TriggerAttack',
                request_serializer=attack__pb2.TriggerAttackRequest.SerializeToString,
                response_deserializer=attack__pb2.TriggerAttackResponse.FromString,
                )
        self.ClearTracks = channel.unary_unary(
                '/Attack/ClearTracks',
                request_serializer=attack__pb2.ClearTracksRequest.SerializeToString,
                response_deserializer=attack__pb2.ClearTracksResponse.FromString,
                )


class AttackServicer(object):
    """Interface exported by the server
    a Attack service
    """

    def FindAMachine(self, request, context):
        """FindAMachine obtains the MachinesUpResponse from a given FindAMachineRequest  
        a list of active host machines in a given subnet mask

        A subnet mask that has no active machines returns an empty list 
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FingerPrint(self, request, context):
        """FingerPrint obtains a list of ports that are open on a given active host

        A active host that has no found open ports returns an empty list
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GainAccess(self, request, context):
        """GainAccess obtains the results of attempting to gain access into a target host by using
        a given set of machine information about the target and returns a Boolean value gainedAccess
        reflecting whether access was gained. If access was gained GainAccess would also
        obtain the username, password combination along with the access method used. 

        A unsuccessful attempt to gain access returns a Boolean value gainedAccess 
        along with an empty string for username, password, and accessMethod
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def AddBackdoor(self, request, context):
        """AddBackDoor obtains the response of attempting to install a backdoor command in a
        given target machine after using the correct username and password combination to log in via
        the found access method. 

        AddBackDoorResponse returns a backdoorCommandResponse string that states the results
        of the given command
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def TriggerAttack(self, request, context):
        """TriggerAttack obtains the response of attempting to perform an attack command in a
        given target machine after using the correct username and password combination to log in via
        the found access method

        TriggerAttackResponse returns a attackResponse string stating the results of the initiated
        attack command
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ClearTracks(self, request, context):
        """ClearTracks obtains the response of a ClearTracksRequest Boolean value removeLogs
        that determines whether to remove logs.

        ClearTracksResponse returns back a populated removeLogCommandResponse string if the
        removeLogs Boolean value passed in is set to true
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_AttackServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'FindAMachine': grpc.unary_unary_rpc_method_handler(
                    servicer.FindAMachine,
                    request_deserializer=attack__pb2.FindAMachineRequest.FromString,
                    response_serializer=attack__pb2.MachinesUpResponse.SerializeToString,
            ),
            'FingerPrint': grpc.unary_unary_rpc_method_handler(
                    servicer.FingerPrint,
                    request_deserializer=attack__pb2.FingerPrintMachineRequest.FromString,
                    response_serializer=attack__pb2.FingerPrintResponse.SerializeToString,
            ),
            'GainAccess': grpc.unary_unary_rpc_method_handler(
                    servicer.GainAccess,
                    request_deserializer=attack__pb2.GainAccessRequest.FromString,
                    response_serializer=attack__pb2.GainAccessResponse.SerializeToString,
            ),
            'AddBackdoor': grpc.unary_unary_rpc_method_handler(
                    servicer.AddBackdoor,
                    request_deserializer=attack__pb2.AddBackdoorRequest.FromString,
                    response_serializer=attack__pb2.AddBackdoorResponse.SerializeToString,
            ),
            'TriggerAttack': grpc.unary_unary_rpc_method_handler(
                    servicer.TriggerAttack,
                    request_deserializer=attack__pb2.TriggerAttackRequest.FromString,
                    response_serializer=attack__pb2.TriggerAttackResponse.SerializeToString,
            ),
            'ClearTracks': grpc.unary_unary_rpc_method_handler(
                    servicer.ClearTracks,
                    request_deserializer=attack__pb2.ClearTracksRequest.FromString,
                    response_serializer=attack__pb2.ClearTracksResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'Attack', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class Attack(object):
    """Interface exported by the server
    a Attack service
    """

    @staticmethod
    def FindAMachine(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Attack/FindAMachine',
            attack__pb2.FindAMachineRequest.SerializeToString,
            attack__pb2.MachinesUpResponse.FromString,
            options, channel_credentials,
            call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FingerPrint(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Attack/FingerPrint',
            attack__pb2.FingerPrintMachineRequest.SerializeToString,
            attack__pb2.FingerPrintResponse.FromString,
            options, channel_credentials,
            call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GainAccess(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Attack/GainAccess',
            attack__pb2.GainAccessRequest.SerializeToString,
            attack__pb2.GainAccessResponse.FromString,
            options, channel_credentials,
            call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def AddBackdoor(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Attack/AddBackdoor',
            attack__pb2.AddBackdoorRequest.SerializeToString,
            attack__pb2.AddBackdoorResponse.FromString,
            options, channel_credentials,
            call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def TriggerAttack(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Attack/TriggerAttack',
            attack__pb2.TriggerAttackRequest.SerializeToString,
            attack__pb2.TriggerAttackResponse.FromString,
            options, channel_credentials,
            call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ClearTracks(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Attack/ClearTracks',
            attack__pb2.ClearTracksRequest.SerializeToString,
            attack__pb2.ClearTracksResponse.FromString,
            options, channel_credentials,
            call_credentials, compression, wait_for_ready, timeout, metadata)
