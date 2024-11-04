import gradio as gr
import pyshark
import threading
import netifaces
import time

# 全局变量用于控制抓包线程
capture_thread = None
stop_event = threading.Event()
pause_event = threading.Event()

def capture_traffic(interface: str, duration: int) -> str:
    global capture_thread, stop_event, pause_event
    stop_event.clear()
    pause_event.set()  # 初始状态为非暂停
    print(f"开始抓取 {interface} 网卡的数据包，时长 {duration} 秒")
    capture = pyshark.LiveCapture(interface=interface)
    packets = []

    def start_capture(progress):
        start_time = time.time()
        while time.time() - start_time < duration:
            if stop_event.is_set():
                break
            if pause_event.is_set():
                capture.sniff(packet_count=1)
                packets.extend(capture._packets)
                elapsed_time = time.time() - start_time
                progress((elapsed_time / duration) * 100)
            else:
                time.sleep(0.1)  # 暂停时稍作等待

    progress = gr.Progress(track_tqdm=True)
    capture_thread = threading.Thread(target=start_capture, args=(progress,))
    capture_thread.start()
    capture_thread.join()

    # 分析捕获的数据包
    total_packets = len(packets)
    protocols = {}
    for packet in packets:
        proto = packet.highest_layer
        protocols[proto] = protocols.get(proto, 0) + 1

    result = f"捕获了 {total_packets} 个数据包。\n协议分布：\n"
    print(result)
    for proto, count in protocols.items():
        result += f"{proto}: {count}\n"
        print(f"{proto}: {count}")
    return result

def stop_capture():
    global stop_event
    stop_event.set()
    if capture_thread:
        capture_thread.join()
    return "抓包已终止"

def pause_capture():
    global pause_event
    pause_event.clear()
    return "抓包已暂停"

def resume_capture():
    global pause_event
    pause_event.set()
    return "抓包已恢复"

def get_interfaces():
    return netifaces.interfaces()

iface_list = get_interfaces()

with gr.Blocks() as demo:
    gr.Markdown("# 简单流量分析工具")
    iface = gr.Dropdown(choices=iface_list, label="请选择网卡")
    duration = gr.Slider(minimum=1, maximum=60, value=10, label="抓取时长（秒）")
    output = gr.Textbox(label="结果")
    
    with gr.Row():
        btn_start = gr.Button("开始抓取")
        btn_stop = gr.Button("终止抓取")
        btn_pause = gr.Button("暂停抓取")
        btn_resume = gr.Button("恢复抓取")

    btn_start.click(capture_traffic, inputs=[iface, duration], outputs=output)
    btn_stop.click(stop_capture, outputs=output)
    btn_pause.click(pause_capture, outputs=output)
    btn_resume.click(resume_capture, outputs=output)

demo.launch()