import pyshark
import csv

def parse_pcap_to_csv(pcap_file, eth_csv, ip_csv, tcp_csv, udp_csv, http_csv, summary_csv):
    packets = pyshark.FileCapture(pcap_file)
    
    with open(eth_csv, 'w', newline='') as ethfile, \
         open(ip_csv, 'w', newline='') as ipfile, \
         open(tcp_csv, 'w', newline='') as tcpfile, \
         open(udp_csv, 'w', newline='') as udpfile, \
         open(http_csv, 'w', newline='') as httpfile, \
         open(summary_csv, 'w', newline='') as summaryfile:
        
        eth_writer = csv.writer(ethfile)
        ip_writer = csv.writer(ipfile)
        tcp_writer = csv.writer(tcpfile)
        udp_writer = csv.writer(udpfile)
        http_writer = csv.writer(httpfile)
        summary_writer = csv.writer(summaryfile)
        
        # 写入CSV表头
        eth_writer.writerow(['Seq', 'Timestamp', 'Dest MAC', 'Src MAC', 'Proto'])
        ip_writer.writerow(['Seq', 'Timestamp', 'Version', 'Total Length', 'Identification', 'Flags', 'Fragment Offset', 'TTL', 'Protocol', 'Header Checksum', 'Src IP', 'Dest IP'])
        tcp_writer.writerow(['Seq', 'Timestamp', 'Src Port', 'Dest Port', 'Sequence', 'Acknowledgment', 'Flags', 'Window Size', 'Checksum', 'Urgent Pointer'])
        udp_writer.writerow(['Seq', 'Timestamp', 'Src Port', 'Dest Port', 'Length', 'Checksum'])
        http_writer.writerow(['Seq', 'Timestamp', 'File Data'])
        summary_writer.writerow(['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length'])
        
        for seq, packet in enumerate(packets):
            timestamp = packet.sniff_time
            length = packet.length
            
            if hasattr(packet, 'eth'):
                eth = packet.eth
                eth_writer.writerow([seq, timestamp, eth.dst, eth.src, eth.type])
            
            if hasattr(packet, 'ip'):
                ip = packet.ip
                ip_writer.writerow([seq, timestamp, getattr(ip, 'version', 'N/A'), getattr(ip, 'len', 'N/A'), getattr(ip, 'id', 'N/A'), getattr(ip, 'flags', 'N/A'), str(getattr(ip, 'frag_offset', 'N/A')), getattr(ip, 'ttl', 'N/A'), getattr(ip, 'proto', 'N/A'), getattr(ip, 'checksum', 'N/A'), getattr(ip, 'src', 'N/A'), getattr(ip, 'dst', 'N/A')])
            
            if hasattr(packet, 'tcp'):
                tcp = packet.tcp
                tcp_writer.writerow([seq, timestamp, getattr(tcp, 'srcport', 'N/A'), getattr(tcp, 'dstport', 'N/A'), getattr(tcp, 'seq', 'N/A'), getattr(tcp, 'ack', 'N/A'), getattr(tcp, 'flags', 'N/A'), getattr(tcp, 'window_size', 'N/A'), getattr(tcp, 'checksum', 'N/A'), getattr(tcp, 'urgent_pointer', 'N/A')])
            
            if hasattr(packet, 'udp'):
                udp = packet.udp
                udp_writer.writerow([seq, timestamp, getattr(udp, 'srcport', 'N/A'), getattr(udp, 'dstport', 'N/A'), getattr(udp, 'length', 'N/A'), getattr(udp, 'checksum', 'N/A')])
            
            if hasattr(packet, 'http'):
                http = packet.http
                http_writer.writerow([seq, timestamp, getattr(http, 'file_data', 'N/A')])
            
            proto = packet.highest_layer
            summary_writer.writerow([seq, timestamp, packet.ip.src if hasattr(packet, 'ip') else 'N/A', packet.ip.dst if hasattr(packet, 'ip') else 'N/A', proto, length])
    packets.close()
    
    return eth_csv, ip_csv, tcp_csv, udp_csv, http_csv, summary_csv

# 调用函数