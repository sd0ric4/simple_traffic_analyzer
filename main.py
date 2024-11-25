import gradio as gr
import pyshark
import threading
import netifaces
import time
import pandas as pd
from utils.pcap2csv import parse_pcap_to_csv
import matplotlib.pyplot as plt


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

def capture_traffic(interface, duration, outputfile, bpf_filter):
    global capture_thread, stop_event, pause_event
    stop_event.clear()
    pause_event.set()  # 初始状态为非暂停
    print(f"开始抓取 {interface} 网卡的数据包，时长 {duration} 秒，过滤器：{bpf_filter}")
    capture = pyshark.LiveCapture(interface=interface, output_file=outputfile, bpf_filter=bpf_filter)

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

# 修改 start_capture 函数以接受过滤器参数
def start_capture(interface, duration, bpf_filter):
    output_file = f"capture_{int(time.time())}.pcap"
    result, file_path = capture_traffic(interface=interface, duration=duration, outputfile=output_file, bpf_filter=bpf_filter)
    return result, file_path

def to_form(file):
    global df_ethernet, df_ip, df_tcp, df_udp, df_http, df_summary
    df_ethernet, df_ip, df_tcp, df_udp, df_http, df_summary = parse_pcap_to_csv(file, 'ethernet.csv', 'ip.csv', 'tcp.csv', 'udp.csv', 'http.csv', 'summary.csv')
    tmp_DataFrame = pd.read_csv('summary.csv') # 读取汇总数据
    
    protocol_counts = tmp_DataFrame['Protocol'].value_counts()
    
    # 打印调试信息
    print(protocol_counts)
    
    # 使用matplotlib生成美观的饼状图
    fig, ax = plt.subplots(figsize=(10, 6), dpi=1000)
    colors = plt.cm.Paired(range(len(protocol_counts)))
    wedges, texts, autotexts = ax.pie(
        protocol_counts.values, 
        labels=protocol_counts.index, 
        autopct='%1.1f%%', 
        startangle=140, 
        colors=colors, 
    )
    ax.set_title("Protocol Distribution")
    ax.legend(wedges, protocol_counts.index, title="Protocal", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
    plt.setp(autotexts, size=10, weight="bold", color="white")
    
    return df_ethernet, df_ip, df_tcp, df_udp, df_http, df_summary, fig

def search_record(index):
    global df_summary, df_ethernet, df_ip, df_tcp, df_udp, df_http
    pd_summary = pd.read_csv(df_summary)
    pd_ethernet = pd.read_csv(df_ethernet)
    pd_ip = pd.read_csv(df_ip)
    pd_tcp = pd.read_csv(df_tcp)
    pd_udp = pd.read_csv(df_udp)
    pd_http = pd.read_csv(df_http)
    print(index)
    print("summary的长度：", len(df_summary))
    print("summary的内容：\n", pd_summary)
    if index < 0 or index >= len(pd_summary):
        return "无效的序号", None, None, None, None, None
    print(df_summary)
    record = pd_summary.iloc[index]
    filtered_df_ethernet = pd_ethernet[pd_ethernet['Seq'] == record['No']]
    filtered_df_ip = pd_ip[pd_ip['Seq'] == record['No']]
    filtered_df_tcp = pd_tcp[pd_tcp['Seq'] == record['No']]
    filtered_df_udp = pd_udp[pd_udp['Seq'] == record['No']]
    filtered_df_http = pd_http[pd_http['Seq'] == record['No']]
    
    return "搜索完成", filtered_df_ethernet, filtered_df_ip, filtered_df_tcp, filtered_df_udp, filtered_df_http

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
    df = pd.read_csv(file.name)
    return df

iface_list = get_interfaces()

with gr.Blocks() as demo:
    gr.Markdown("# 简单流量分析工具")
    iface = gr.Dropdown(choices=iface_list, label="请选择网卡")
    duration = gr.Slider(minimum=1, maximum=60, value=10, label="抓取时长（秒）")
    bpf_filter = gr.Textbox(label="BPF过滤器")
    output = gr.Textbox(label="结果")
    download_link = gr.File(label="下载PCAP文件")
    with gr.Row():
        btn_start = gr.Button("开始抓取")
        btn_stop = gr.Button("终止抓取")
        btn_pause = gr.Button("暂停抓取")
        btn_resume = gr.Button("恢复抓取")

    btn_start.click(start_capture, inputs=[iface, duration, bpf_filter], outputs=[output, download_link])
    btn_stop.click(stop_capture, outputs=output)
    btn_pause.click(pause_capture, outputs=output)
    btn_resume.click(resume_capture, outputs=output)

    gr.Markdown("## 数据包分析")
    btn_to_form = gr.Button("转换为表单")
    df_ethernet_output = gr.Dataframe(label="以太网")
    df_ip_output = gr.Dataframe(label="IP")
    df_tcp_output = gr.Dataframe(label="TCP")
    df_udp_output = gr.Dataframe(label="UDP")
    df_http_output = gr.Dataframe(label="HTTP")
    df_summary_output = gr.Dataframe(label="汇总")
    gr.Markdown("### 协议分布")
    protocol_pie_chart = gr.Plot()
    btn_to_form.click(to_form, inputs=[download_link], outputs=[df_ethernet_output, df_ip_output, df_tcp_output, df_udp_output, df_http_output, df_summary_output, protocol_pie_chart])

    gr.Markdown("## 搜索记录")
    search_index = gr.Number(label="输入序号")
    search_output = gr.Textbox(label="搜索结果")
    search_btn = gr.Button("搜索")
    search_df_ethernet_output = gr.Dataframe(label="以太网")
    search_df_ip_output = gr.Dataframe(label="IP")
    search_df_tcp_output = gr.Dataframe(label="TCP")
    search_df_udp_output = gr.Dataframe(label="UDP")
    search_df_http_output = gr.Dataframe(label="HTTP")
    search_btn.click(search_record, inputs=[search_index], outputs=[search_output,search_df_ethernet_output, search_df_ip_output, search_df_tcp_output, search_df_udp_output, search_df_http_output])

demo.launch(server_name="0.0.0.0", server_port=7878)