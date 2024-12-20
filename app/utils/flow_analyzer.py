# -*- coding:utf-8 -*-

# 导入所需的网络协议相关模块
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.all import corrupt_bytes

# 导入数据处理相关模块
import collections
import time


# 时间流量图
def time_flow(PCAPS):
    """
    生成时间-流量统计图数据
    Args:
        PCAPS: 数据包列表
    Returns:
        OrderedDict: 时间点和对应的数据包大小
    """
    time_flow_dict = collections.OrderedDict()
    start = float(PCAPS[0].time)
    time_flow_dict[
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start))
    ] = len(corrupt_bytes(PCAPS[0]))
    for pcap in PCAPS[1:]:
        timediff = float(pcap.time) - start
        time_flow_dict[float("%.3f" % timediff)] = len(corrupt_bytes(pcap))
    return time_flow_dict


# 获取抓包主机的IP
def get_host_ip(PCAPS):
    """
    通过分析数据包获取本机IP地址
    Args:
        PCAPS: 数据包列表
    Returns:
        str: 出现次数最多的IP地址,即本机IP
    """
    ip_list = list()
    
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            ip_list.append(pcap.getlayer(IP).src)
            ip_list.append(pcap.getlayer(IP).dst)
    
    # 添加错误处理
    if not ip_list:
        return None
        
    counter = collections.Counter(ip_list)
    most_common = counter.most_common()
    
    return most_common[0][0] if most_common else None


# 数据流入流出统计
def data_flow(PCAPS, host_ip):
    """
    统计数据包的流入流出数量
    Args:
        PCAPS: 数据包列表
        host_ip: 本机IP
    Returns:
        dict: 包含流入(IN)和流出(OUT)的数据包数量
    """
    data_flow_dict = {"IN": 0, "OUT": 0}
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            if pcap.getlayer(IP).src == host_ip:
                data_flow_dict["OUT"] += 1
            elif pcap.getlayer(IP).dst == host_ip:
                data_flow_dict["IN"] += 1
            else:
                pass
    return data_flow_dict


# 访问IP地址统计
def data_in_out_ip(PCAPS, host_ip):
    """
    统计与本机通信的IP地址及其流量
    Args:
        PCAPS: 数据包列表
        host_ip: 本机IP
    Returns:
        dict: 包含流入流出IP的数据包数量和总字节数统计
    """
    in_ip_packet_dict = dict()
    in_ip_len_dict = dict()
    out_ip_packet_dict = dict()
    out_ip_len_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            dst = pcap.getlayer(IP).dst
            src = pcap.getlayer(IP).src
            pcap_len = len(corrupt_bytes(pcap))
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len
            else:
                pass

    in_packet_dict = in_ip_packet_dict
    in_len_dict = in_ip_len_dict
    out_packet_dict = out_ip_packet_dict
    out_len_dict = out_ip_len_dict
    in_packet_dict = sorted(in_packet_dict.items(), key=lambda d: d[1], reverse=False)
    in_len_dict = sorted(in_len_dict.items(), key=lambda d: d[1], reverse=False)
    out_packet_dict = sorted(out_packet_dict.items(), key=lambda d: d[1], reverse=False)
    out_len_dict = sorted(out_len_dict.items(), key=lambda d: d[1], reverse=False)

    in_keyp_list = list()
    in_packet_list = list()
    for key, value in in_packet_dict:
        in_keyp_list.append(key)
        in_packet_list.append(value)

    in_keyl_list = list()
    in_len_list = list()
    for key, value in in_len_dict:
        in_keyl_list.append(key)
        in_len_list.append(value)

    out_keyp_list = list()
    out_packet_list = list()
    for key, value in out_packet_dict:
        out_keyp_list.append(key)
        out_packet_list.append(value)

    out_keyl_list = list()
    out_len_list = list()
    for key, value in out_len_dict:
        out_keyl_list.append(key)
        out_len_list.append(value)

    in_ip_dict = {
        "in_keyp": in_keyp_list,
        "in_packet": in_packet_list,
        "in_keyl": in_keyl_list,
        "in_len": in_len_list,
        "out_keyp": out_keyp_list,
        "out_packet": out_packet_list,
        "out_keyl": out_keyl_list,
        "out_len": out_len_list,
    }
    return in_ip_dict


# 常见协议流量统计
def proto_flow(PCAPS):
    """
    统计各种网络协议的流量
    Args:
        PCAPS: 数据包列表
    Returns:
        OrderedDict: 各协议的总字节数统计
    """
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict["IP"] = 0
    proto_flow_dict["IPv6"] = 0
    proto_flow_dict["TCP"] = 0
    proto_flow_dict["UDP"] = 0
    proto_flow_dict["ARP"] = 0
    proto_flow_dict["ICMP"] = 0
    proto_flow_dict["DNS"] = 0
    proto_flow_dict["HTTP"] = 0
    proto_flow_dict["HTTPS"] = 0
    proto_flow_dict["Others"] = 0
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if pcap.haslayer(IP):
            proto_flow_dict["IP"] += pcap_len
        elif pcap.haslayer(IPv6):
            proto_flow_dict["IPv6"] += pcap_len
        if pcap.haslayer(TCP):
            proto_flow_dict["TCP"] += pcap_len
        elif pcap.haslayer(UDP):
            proto_flow_dict["UDP"] += pcap_len
        if pcap.haslayer(ARP):
            proto_flow_dict["ARP"] += pcap_len
        elif pcap.haslayer(ICMP):
            proto_flow_dict["ICMP"] += pcap_len
        elif pcap.haslayer(DNS):
            proto_flow_dict["DNS"] += pcap_len
        elif pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                proto_flow_dict["HTTP"] += pcap_len
            elif dport == 443 or sport == 443:
                proto_flow_dict["HTTPS"] += pcap_len
            else:
                proto_flow_dict["Others"] += pcap_len
        elif pcap.haslayer(UDP):
            udp = pcap.getlayer(UDP)
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                proto_flow_dict["DNS"] += pcap_len
            else:
                proto_flow_dict["Others"] += pcap_len
        elif pcap.haslayer(ICMPv6ND_NS):
            proto_flow_dict["ICMP"] += pcap_len
        else:
            proto_flow_dict["Others"] += pcap_len
    return proto_flow_dict


# 流量多协议数量统计
def most_flow_statistic(PCAPS, PD):
    """
    统计各协议的流量大小
    Args:
        PCAPS: 数据包列表
        PD: 协议解码器对象
    Returns:
        defaultdict: 各协议的总字节数统计
    """
    most_flow_dict = collections.defaultdict(int)
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        most_flow_dict[data["Procotol"]] += len(corrupt_bytes(pcap))
    return most_flow_dict
