# utils/packet_parser.py

import struct
import socket

class EthernetFrame:
    def __init__(self, raw_data):
        dest_mac, src_mac, proto_type = struct.unpack('!6s6sH', raw_data[:14])
        self.dest_mac = self._format_mac(dest_mac)
        self.src_mac = self._format_mac(src_mac)
        self.proto = socket.ntohs(proto_type)
        self.data = raw_data[14:]

    def _format_mac(self, bytes_addr):
        return ':'.join(format(b, '02x') for b in bytes_addr)

class IPv4Packet:
    def __init__(self, raw_data):
        version_ihl = raw_data[0]
        self.version = version_ihl >> 4
        self.ihl = (version_ihl & 0xF) * 4
        self.tos, self.total_length, self.identification, flags_offset, self.fragment_offset, self.ttl, self.protocol, self.header_checksum, src, target = struct.unpack('!BBHHHBBH4s4s', raw_data[:20])
        self.flags = flags_offset >> 13
        self.fragment_offset = flags_offset & 0x1FFF
        self.src_ip = self._format_ip(src)
        self.dest_ip = self._format_ip(target)
        self.data = raw_data[self.ihl:]

    def _format_ip(self, addr):
        return '.'.join(map(str, addr))

class TCPSegment:
    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags, self.window_size, self.checksum, self.urgent_pointer) = struct.unpack(
            '!HHLLHHHH', raw_data[:20])
        self.offset = (offset_reserved_flags >> 12) * 4
        self.flags = {
            'URG': (offset_reserved_flags & 32) >> 5,
            'ACK': (offset_reserved_flags & 16) >> 4,
            'PSH': (offset_reserved_flags & 8) >> 3,
            'RST': (offset_reserved_flags & 4) >> 2,
            'SYN': (offset_reserved_flags & 2) >> 1,
            'FIN': offset_reserved_flags & 1
        }
        self.data = raw_data[self.offset:]

class UDPSegment:
    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.length, self.checksum = struct.unpack('!HHHH', raw_data[:8])
        self.data = raw_data[8:]

class HTTPData:
    def __init__(self, raw_data):
        try:
            self.text = raw_data.decode('utf-8')
        except UnicodeDecodeError:
            self.text = raw_data

# 示例用法：
# 从网络接口获取原始数据 raw_data
# eth_frame = EthernetFrame(raw_data)
# if eth_frame.proto == 8:  # IP 协议
#     ip_packet = IPv4Packet(eth_frame.data)
#     if ip_packet.protocol == 6:  # TCP 协议
#         tcp_segment = TCPSegment(ip_packet.data)
#         if tcp_segment.src_port == 80 or tcp_segment.dest_port == 80:
#             http_data = HTTPData(tcp_segment.data)
#             print(http_data.text)
#     elif ip_packet.protocol == 17:  # UDP 协议
#         udp_segment = UDPSegment(ip_packet.data)
#         # 处理 UDP 数据