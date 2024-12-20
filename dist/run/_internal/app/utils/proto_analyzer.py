# -*- coding:utf-8 -*-

from scapy.all import corrupt_bytes
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
import collections


# 数据包大小统计
def pcap_len_statistic(PCAPS):
    """
    统计数据包大小分布
    Args:
        PCAPS: 数据包列表
    Returns:
        dict: 不同大小范围的数据包数量统计
    """
    pcap_len_dict = {
        "0-300": 0,
        "301-600": 0, 
        "601-900": 0,
        "901-1200": 0,
        "1201-1500": 0
    }
    
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if pcap_len <= 300:
            pcap_len_dict["0-300"] += 1
        elif pcap_len <= 600:
            pcap_len_dict["301-600"] += 1
        elif pcap_len <= 900:
            pcap_len_dict["601-900"] += 1
        elif pcap_len <= 1200:
            pcap_len_dict["901-1200"] += 1
        elif pcap_len <= 1500:
            pcap_len_dict["1201-1500"] += 1
            
    return pcap_len_dict


# 常见协议统计
def common_proto_statistic(PCAPS):
    """
    统计常见协议的数量
    Args:
        PCAPS: 数据包列表
    Returns:
        OrderedDict: 各协议的数量统计
    """
    common_proto_dict = collections.OrderedDict({
        "IP": 0, "IPv6": 0, "TCP": 0, "UDP": 0,
        "ARP": 0, "ICMP": 0, "DNS": 0, "HTTP": 0,
        "HTTPS": 0, "Others": 0
    })

    for pcap in PCAPS:
        # IP层协议统计
        if pcap.haslayer(IP):
            common_proto_dict["IP"] += 1
        elif pcap.haslayer(IPv6):
            common_proto_dict["IPv6"] += 1
            
        # 传输层协议统计    
        if pcap.haslayer(TCP):
            common_proto_dict["TCP"] += 1
            tcp = pcap.getlayer(TCP)
            if tcp.dport in (80, 443) or tcp.sport in (80, 443):
                common_proto_dict["HTTP" if tcp.dport == 80 or tcp.sport == 80 else "HTTPS"] += 1
            else:
                common_proto_dict["Others"] += 1
        elif pcap.haslayer(UDP):
            common_proto_dict["UDP"] += 1
            udp = pcap.getlayer(UDP)
            if udp.dport == 5353 or udp.sport == 5353:
                common_proto_dict["DNS"] += 1
            else:
                common_proto_dict["Others"] += 1
                
        # 其他协议统计
        if pcap.haslayer(ARP):
            common_proto_dict["ARP"] += 1
        elif pcap.haslayer(ICMP) or pcap.haslayer(ICMPv6ND_NS):
            common_proto_dict["ICMP"] += 1
        elif pcap.haslayer(DNS):
            common_proto_dict["DNS"] += 1
        else:
            common_proto_dict["Others"] += 1
            
    return common_proto_dict


# 最多协议数量统计
def most_proto_statistic(PCAPS, PD):
    """
    统计出现次数最多的协议
    Args:
        PCAPS: 数据包列表
        PD: 协议解码器对象
    Returns:
        OrderedDict: 前10个最常见协议的统计
    """
    protos_list = [PD.ether_decode(pcap)["Procotol"] for pcap in PCAPS]
    return collections.OrderedDict(collections.Counter(protos_list).most_common(10))


# HTTP/HTTPS协议统计
def http_statistic(PCAPS):
    """
    统计HTTP/HTTPS流量的IP地址分布
    Args:
        PCAPS: 数据包列表
    Returns:
        dict: 各IP地址的HTTP/HTTPS请求数量
    """
    http_dict = collections.defaultdict(int)
    
    for pcap in PCAPS:
        if pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            if tcp.dport in (80, 443):
                http_dict[pcap.getlayer(IP).dst] += 1
            elif tcp.sport in (80, 443):
                http_dict[pcap.getlayer(IP).src] += 1
                
    return dict(http_dict)


# DNS协议统计
def dns_statistic(PCAPS):
    """
    统计DNS查询域名的分布
    Args:
        PCAPS: 数据包列表
    Returns:
        dict: 各域名的查询次数统计
    """
    dns_dict = collections.defaultdict(int)
    
    for pcap in PCAPS:
        if pcap.haslayer(DNSQR):
            dns_dict[pcap.getlayer(DNSQR).qname] += 1
            
    return dict(dns_dict)
