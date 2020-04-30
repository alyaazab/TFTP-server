import sys
import os
import enum
import socket
import struct

class TftpProcessor(object):
    """
    Implements logic for a TFTP server.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.
    """

    # represents the TFTP packet type
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    
    def __init__(self):
        # buffer to store output packets
        self.packet_buffer = []

        # client address
        self.client_address = None

        # output filename
        self.output_fname = ""

        # when a file is read into a byte array, it is stored here
        self.input_bytesarr = []

        # a dictionary that holds each error code and its corresponding error message
        self.errors_dict = {
            0 : "Not defined, see error message.",
            1 : "File not found.",
            4 : "Illegal TFTP operation.",
            6 : "File already exists."
            }

        # flag that indicates if we need to terminate
        # 0: no termination
        # 1: sent last DATA packet, waiting for ACK
        # 2: sent error packet- terminate
        # 3: ACK received for last packet, terminate
        self.termination_flag = 0
    

    # reset values of all instance variables to be able to service a new client or request
    def reset(self):
        self.termination_flag = 0
        self.client_address = None
        self.input_bytesarr = []
        self.output_fname = ""


    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")

        # parse input packet
        in_packet = self._parse_udp_packet(packet_data)

        # create output packet
        out_packet = self._generate_output_packet(in_packet)

        # append output packet to packet buffer
        self.packet_buffer.append(out_packet)


    def _parse_udp_packet(self, packet_bytes):
        
        # use struct module to determine the type of packet received and unpack it

        packet_bytesarr = list(packet_bytes)
        opcode = packet_bytesarr[1]
        format_string = "!h"


        if opcode == self.TftpPacketType.RRQ.value or opcode == self.TftpPacketType.WRQ.value:
            # search for the first string delimiter (which terminates the "filename" field)
            first_zero_idx = packet_bytesarr.index(0, 1)
            # calculate the length of the "filename" field
            filename_len = first_zero_idx - 2
            # find the second string delimiter (which terminates the "mode" field)
            sec_zero_idx = packet_bytesarr.index(0,first_zero_idx + 1)
            # calculate the length of the "mode" field
            mode_len = sec_zero_idx - first_zero_idx - 1
            # update format string
            format_string += str(filename_len) + "sc" + str(mode_len) + "sc"

            packet_bytes = packet_bytes[:sec_zero_idx+1]
        
        elif opcode == self.TftpPacketType.DATA.value:
            format_string += "h" + str(len(packet_bytesarr) - 4) + "s"
            
            # if we have received the last DATA packet
            if len(packet_bytesarr) - 4 < 512:
                self.termination_flag = 2
        
        elif opcode == self.TftpPacketType.ACK.value:
            format_string += "h"

            # if we have received the last ACK
            if self.termination_flag == 1:
                self.termination_flag = 3

            packet_bytes = packet_bytes[:4]
        
        elif opcode == self.TftpPacketType.ERROR.value:
            zero_idx = packet_bytesarr.index(0, 4)
            format_string += "h" + str(zero_idx-4) + "sc"
            
            packet_bytes = packet_bytes[:zero_idx+1]
        
        else:
            # dummy list in case the client sends an incorrect opcode
            err = bytearray([0, 6])
            return list(struct.unpack("!h", err))

        # return a list of the unpacked received packet
        return list(struct.unpack(format_string, packet_bytes))


    def _generate_output_packet(self, input_packet):
        
        # input_packet is a list of unpacked bytes from the received packet
        opcode = input_packet[0]
        format_string = "!h"

        # if client sends RRQ, respond with a DATA packet if file is found
        # else, respond with an ERROR packet
        if opcode == self.TftpPacketType.RRQ.value:
            try:
                # read entire file into a byte array
                self.input_bytesarr = open(input_packet[1], "rb").read()

                # extract the first 512 bytes to send in output packet
                bytes_to_send = self.input_bytesarr[:512] 
                format_string += "h" + str(len(bytes_to_send)) + "s"

                if len(bytes_to_send) < 512:
                    self.termination_flag = 1

                # generate DATA packet
                packed_data = struct.pack(format_string, self.TftpPacketType.DATA.value, 1, bytes_to_send)
            except FileNotFoundError:
                # file not found, generate ERROR packet with code 1
                self.termination_flag = 2
                format_string += "h" + str(len(self.errors_dict[1])) + "sB"
                packed_data = struct.pack(format_string, self.TftpPacketType.ERROR.value, 1, (self.errors_dict[1]).encode("ascii"), 0)
            finally:
                pass
        
        # if client sends WRQ, respond with an ACK packet
        elif opcode == self.TftpPacketType.WRQ.value:
            format_string += "h"
            self.output_fname = input_packet[1]
            packed_data = struct.pack(format_string, self.TftpPacketType.ACK.value, 0)

        # if client sends DATA, write it to file and respond with an ACK packet
        elif opcode == self.TftpPacketType.DATA.value:
            format_string += "h"
            if input_packet[1] == 1:
                new_file = open(self.output_fname, "wb")
            else:
                new_file = open(self.output_fname, "ab")
            new_file.write(input_packet[2])
            packed_data = struct.pack(format_string, self.TftpPacketType.ACK.value, input_packet[1])

        
        # if client sends ACK, respond with DATA packet
        elif opcode == self.TftpPacketType.ACK.value:
            block_num = input_packet[1] + 1
            bytes_to_send = self.input_bytesarr[512*(block_num-1) : 512*block_num : 1]
            format_string += "h" + str(len(bytes_to_send)) + "s"
            packed_data = struct.pack(format_string, self.TftpPacketType.DATA.value, block_num, bytes_to_send)

            # if we have sent the last DATA packet
            if len(bytes_to_send) < 512 and self.termination_flag!=3:
                    self.termination_flag = 1
        
        # if client sends incorrect opcode, respond with ERROR packet 
        else:
            print("Illegal TFTP Operation")
            self.termination_flag = 2
            format_string += "h" + str(len(self.errors_dict[4])) + "sB"
            packed_data = struct.pack(format_string, self.TftpPacketType.ERROR.value, 1, (self.errors_dict[4]).encode("ascii"), 0)
            
        return packed_data


    def get_next_output_packet(self):
        # returns the next packet that needs to be send
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        # returns if any packets to be sent are available
        return len(self.packet_buffer) != 0


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    # create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # server's port number is 69 to align with the TFTP protocol
    server_address = ('127.0.0.1', 69)
    server_socket.bind(server_address)

    print(f"TFTP server started on [{server_address}]...")

    # set socket timeout to 500ms
    server_socket.settimeout(500)

    # start receiving and sending packets
    recv_send_packets(server_socket)
    

def recv_send_packets(server_socket):

    # create a TftpProcessor object
    tftp_proc = TftpProcessor()

    # infinite loop to keep receiving and sending packets from/to client
    while(1):
        # receive a packet from client
        data, client_address = server_socket.recvfrom(4096)

        # if we are not already servicing a client, we can service a new one
        if tftp_proc.client_address is None:
            tftp_proc.client_address = client_address
        elif tftp_proc.client_address != client_address:
            continue

        # tftp_proc = do_socket_logic(rec_packet, tftp_proc)
        tftp_proc.process_udp_packet(data, client_address)


        # if a packet has been added to the buffer, send it to client
        if tftp_proc.has_pending_packets_to_be_sent():
            if tftp_proc.termination_flag == 3:
                tftp_proc.get_next_output_packet()
                tftp_proc.reset()
                continue
            packet = tftp_proc.get_next_output_packet()
            server_socket.sendto(packet, client_address)

        if tftp_proc.termination_flag == 2:
            tftp_proc.reset()
        


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplied, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server.

    ip_address = get_arg(1, "127.0.0.1")
    print(ip_address)
    setup_sockets(ip_address)


if __name__ == "__main__":
    main()