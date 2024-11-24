import pyshark
import threading
import time

# 全局变量用于控制抓包线程
capture_thread = None
stop_event = threading.Event()
pause_event = threading.Event()

def capture_traffic(interface, duration, output_file):
    global capture_thread, stop_event, pause_event
    stop_event = threading.Event()
    pause_event = threading.Event()
    stop_event.clear()
    pause_event.set()  # 初始状态为非暂停
    print(f"开始抓取 {interface} 网卡的数据包，时长 {duration} 秒")
    capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
    packets = []

    def start_capture():
        start_time = time.time()
        for packet in capture.sniff_continuously():
            if stop_event.is_set() or time.time() - start_time >= duration:
                break
        capture.close()


    capture_thread = threading.Thread(target=start_capture)
    capture_thread.start()
    capture_thread.join()

    # 读取抓取的数据包pcap文件
    result = analyze_pcap(output_file)
    return result, output_file
def analyze_pcap(output_file):
    capture = pyshark.FileCapture(output_file)
    packets = list(capture)
    total_packets = len(packets)
    protocols = {}
    
    for packet in packets:
        proto = packet.highest_layer
        protocols[proto] = protocols.get(proto, 0) + 1

    result = f"捕获了 {total_packets} 个数据包。\n协议分布：\n"
    for proto, count in protocols.items():
        result += f"{proto}: {count}\n"
    
    print(result)
    return result

if __name__ == "__main__":
    capture_traffic("enp0s31f6", 3, "capture.pcap")