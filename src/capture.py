import datetime
import struct
import socket
import sys
import time
import os

ethFrame=str("_"*74+"ETHERNET~FRAME"+"_"*74)
sep1="_"*167


# Ethernet Header
class Ethernet:

    def __init__(self, raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
        self.dest_mac = mac_format(dest)
        self.src_mac = mac_format(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]
        self.pac_len = len(raw_data)


# Ipv4 Header
class IPv4:

    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4_format(src)
        self.target = self.ipv4_format(target)
        self.data = raw_data[self.header_length:]

        if self.proto == 1:
        	self.next_proto = 'ICMP'
        elif self.proto == 6:
        	self.next_proto = 'TCP'
        elif self.proto == 17:
        	self.next_proto = 'UDP'
        else:
        	self.next_proto = 'Not Supported'

    # Returns IPv4 address
    def ipv4_format(self, addr):
        return '.'.join(map(str, addr))


# UDP Header
class UDP:

    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.length,self.checksum = struct.unpack('! H H H H', raw_data[:8])
        self.data = raw_data[8:]



# TCP Header
class TCP:

    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_URG = (offset_reserved_flags & 32) >> 5
        self.flag_ACK = (offset_reserved_flags & 16) >> 4
        self.flag_PSH = (offset_reserved_flags & 8) >> 3
        self.flag_RST = (offset_reserved_flags & 4) >> 2
        self.flag_SYN = (offset_reserved_flags & 2) >> 1
        self.flag_FIN = offset_reserved_flags & 1
        self.data = raw_data[offset:]


# ICMP Header
class ICMP:

    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]



# HTTP Data
class HTTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
            return self.data
        except:
            self.data = None
            return self.data



# PCAP file logging for wireshark
class Pcap:

    def __init__(self, filename, lt=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, lt))

    def write(self, data):
        tsec, tuse = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@IIII', tsec, tuse, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()
        


# Socket Creation
def create_socket():

    try:
        if os.name=='nt':
            conn = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.ntohs(0x0003))
            pcap = Pcap('capture.pcap')

        else:
            conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))      
            pcap = Pcap('capture.pcap')
        
        return conn,pcap

    except Pcap.errormsg:

        errorlog = open('errorlog.txt', 'a')
        errorlog.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ' Socket creation failed. Code: ' + str(errormsg[0]) + 'Message ' + errormsg[1] + '\n')
        errorlog.close()
        sys.exit()



# Packet Extraction
def extract_socket(sock):

        raw_data, addr = sock.recvfrom(65565)
        return raw_data



# Format Mac Address AA:BB:CC:DD:EE:FF
def mac_format(mac_addr):
    mac_addr = map('{:02x}'.format, mac_addr)
    return ':'.join(mac_addr).upper()
