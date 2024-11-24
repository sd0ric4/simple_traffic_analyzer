import gradio as gr
import pyshark
import threading
import netifaces
import time
import polars as pl
from utils.pcap2csv import parse_pcap_to_csv

df_http = pl.DataFrame()
df_udp = pl.DataFrame()
df_tcp = pl.DataFrame()
df_ip = pl.DataFrame()
df_ethernet = pl.DataFrame()
df_summary = pl.DataFrame()
# 全局变量用于控制抓包线程
capture_thread = None
stop_event = threading.Event()
pause_event = threading.Event()
def analyze_pcap(output_file):
    capture = pyshark.FileCapture(output_file, use_json=True)
    packets = [packet for packet in capture]
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
def capture_traffic(interface, duration, outputfile):
    global capture_thread, stop_event, pause_event
    stop_event.clear()
    pause_event.set()  # 初始状态为非暂停
    print(f"开始抓取 {interface} 网卡的数据包，时长 {duration} 秒")
    capture = pyshark.LiveCapture(interface=interface, output_file=outputfile)

    def start_capture():
        start_time = time.time()
        for packet in capture.sniff_continuously():
            if stop_event.is_set() or time.time() - start_time >= duration:
                break

    capture_thread = threading.Thread(target=start_capture)
    capture_thread.start()
    capture_thread.join()

    # 分析捕获的数据包
    result = analyze_pcap(outputfile)
    return result, outputfile
def start_capture(interface, duration):
    output_file = f"capture_{int(time.time())}.pcap"
    result, file_path = capture_traffic(interface=interface, duration=duration, outputfile=output_file)
    return result, file_path
def to_form(file):
    df_ethernet, df_ip, df_tcp, df_udp, df_http, df_summary = parse_pcap_to_csv(file, 'ethernet.csv', 'ip.csv', 'tcp.csv', 'udp.csv', 'http.csv', 'summary.csv')
    return df_ethernet, df_ip, df_tcp, df_udp, df_http, df_summary
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
def read_csv(file):
    df = pl.read_csv(file.name)
    return df

iface_list = get_interfaces()


with gr.Blocks() as demo:
    gr.Markdown("# 简单流量分析工具")
    iface = gr.Dropdown(choices=iface_list, label="请选择网卡")
    duration = gr.Slider(minimum=1, maximum=60, value=10, label="抓取时长（秒）")
    output = gr.Textbox(label="结果")
    download_link = gr.File(label="下载PCAP文件")
    with gr.Row():
        btn_start = gr.Button("开始抓取")
        btn_stop = gr.Button("终止抓取")
        btn_pause = gr.Button("暂停抓取")
        btn_resume = gr.Button("恢复抓取")

    btn_start.click(start_capture, inputs=[iface, duration], outputs=[output, download_link])
    btn_stop.click(stop_capture, outputs=output)
    btn_pause.click(pause_capture, outputs=output)
    btn_resume.click(resume_capture, outputs=output)

    gr.Markdown("## 数据包分析")
    btn_to_form = gr.Button("转换为表单")
    df_ethernet_output = gr.Dataframe()
    df_ip_output = gr.Dataframe()
    df_tcp_output = gr.Dataframe()
    df_udp_output = gr.Dataframe()
    df_http_output = gr.Dataframe()
    df_summary_output = gr.Dataframe()
    btn_to_form.click(to_form, inputs=[download_link], outputs=[df_ethernet_output, df_ip_output, df_tcp_output, df_udp_output, df_http_output, df_summary_output])



demo.launch()