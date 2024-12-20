# -*- coding:utf-8 -*-

from scapy.all import corrupt_bytes
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import time
import os


class PcapDecode:
    """
    用于解析pcap文件的类
    包含对以太网、IP、TCP、UDP等协议的解析功能

    Attributes:
        ETHER_DICT: 存储以太网协议字典
        IP_DICT: 存储IP协议字典
        PORT_DICT: 存储端口协议字典
        TCP_DICT: 存储TCP协议字典
        UDP_DICT: 存储UDP协议字典
    """

    def __init__(self):
        # 获取当前文件的目录
        base_dir = os.path.abspath(os.path.dirname(__file__))

        # 构建各协议配置文件的绝对路径
        ether_path = os.path.join(
            base_dir, "protocol", "ETHER"
        )  # ETHER协议配置文件路径
        ip_path = os.path.join(base_dir, "protocol", "IP")  # IP协议配置文件路径
        port_path = os.path.join(base_dir, "protocol", "PORT")  # 端口配置文件路径
        tcp_path = os.path.join(base_dir, "protocol", "TCP")  # TCP协议配置文件路径
        udp_path = os.path.join(base_dir, "protocol", "UDP")  # UDP协议配置文件路径

        # ETHER:读取以太网层协议配置文件
        with open(ether_path, "r", encoding="UTF-8") as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()  # 存储以太网协议字典
        for ether in ethers:
            ether = ether.strip().strip("\n").strip("\r").strip("\r\n")
            self.ETHER_DICT[int(ether.split(":")[0])] = ether.split(":")[1]

        # IP:读取IP层协议配置文件
        with open(ip_path, "r", encoding="UTF-8") as f:
            ips = f.readlines()
        self.IP_DICT = dict()  # 存储IP协议字典
        for ip in ips:
            ip = ip.strip().strip("\n").strip("\r").strip("\r\n")
            self.IP_DICT[int(ip.split(":")[0])] = ip.split(":")[1]

        # PORT:读取应用层协议端口配置文件
        with open(port_path, "r", encoding="UTF-8") as f:
            ports = f.readlines()
        self.PORT_DICT = dict()  # 存储端口协议字典
        for port in ports:
            port = port.strip().strip("\n").strip("\r").strip("\r\n")
            self.PORT_DICT[int(port.split(":")[0])] = port.split(":")[1]

        # TCP:读取TCP层协议配置文件
        with open(tcp_path, "r", encoding="UTF-8") as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()  # 存储TCP协议字典
        for tcp in tcps:
            tcp = tcp.strip().strip("\n").strip("\r").strip("\r\n")
            self.TCP_DICT[int(tcp.split(":")[0])] = tcp.split(":")[1]

        # UDP:读取UDP层协议配置文件
        with open(udp_path, "r", encoding="UTF-8") as f:
            udps = f.readlines()
        self.UDP_DICT = dict()  # 存储UDP协议字典
        for udp in udps:
            udp = udp.strip().strip("\n").strip("\r").strip("\r\n")
            self.UDP_DICT[int(udp.split(":")[0])] = udp.split(":")[1]

    def ether_decode(self, p):
        """
        解析以太网层协议数据包

        Args:
            p: 需要解析的数据包对象

        Returns:
            dict: 包含解析结果的字典,包含以下字段:
                time: 数据包的时间戳
                Source: 源地址
                Destination: 目标地址
                Protocol: 协议类型
                len: 数据包长度
                info: 数据包概要信息
        """
        # 确保 p.time 是一个浮点数
        timestamp = float(p.time)
        data = dict()  # 存储解析结果
        if p.haslayer(Ether):
            data = self.ip_decode(p)  # 解析IP层协议
            return data
        else:
            # 如果没有以太网层，返回未知信息
            data["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            data["Source"] = "Unknow"
            data["Destination"] = "Unknow"
            data["Procotol"] = "Unknow"
            data["len"] = len(corrupt_bytes(p))
            data["info"] = p.summary()
            return data

    def ip_decode(self, p):
        """
        解析IP层协议数据包

        Args:
            p: 需要解析的数据包对象

        Returns:
            dict: 包含解析结果的字典,包含以下字段:
                time: 数据包的时间戳
                Source: 源IP地址
                Destination: 目标IP地址
                Protocol: 协议类型
                len: 数据包长度
                info: 数据包概要信息
        """
        data = dict()  # 存储解析结果
        timestamp = float(p.time)
        if p.haslayer(IP):  # 2048:Internet IP (IPv4)
            ip = p.getlayer(IP)
            if p.haslayer(TCP):  # 6:TCP
                data = self.tcp_decode(p, ip)  # 解析TCP层协议
                return data
            elif p.haslayer(UDP):  # 17:UDP
                data = self.udp_decode(p, ip)  # 解析UDP层协议
                return data
            else:
                # 处理IP协议
                if ip.proto in self.IP_DICT:
                    data["time"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(timestamp)
                    )
                    data["Source"] = ip.src
                    data["Destination"] = ip.dst
                    data["Procotol"] = self.IP_DICT[ip.proto]
                    data["len"] = len(corrupt_bytes(p))
                    data["info"] = p.summary()
                    return data
                else:
                    data["time"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(timestamp)
                    )
                    data["Source"] = ip.src
                    data["Destination"] = ip.dst
                    data["Procotol"] = "IPv4"
                    data["len"] = len(corrupt_bytes(p))
                    data["info"] = p.summary()
                    return data
        elif p.haslayer(IPv6):  # 34525:IPv6
            ipv6 = p.getlayer(IPv6)
            if p.haslayer(TCP):  # 6:TCP
                data = self.tcp_decode(p, ipv6)  # 解析TCP层协议
                return data
            elif p.haslayer(UDP):  # 17:UDP
                data = self.udp_decode(p, ipv6)  # 解析UDP层协议
                return data
            else:
                # 处理IPv6协议
                if ipv6.nh in self.IP_DICT:
                    data["time"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(timestamp)
                    )
                    data["Source"] = ipv6.src
                    data["Destination"] = ipv6.dst
                    data["Procotol"] = self.IP_DICT[ipv6.nh]
                    data["len"] = len(corrupt_bytes(p))
                    data["info"] = p.summary()
                    return data
                else:
                    data["time"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(timestamp)
                    )
                    data["Source"] = ipv6.src
                    data["Destination"] = ipv6.dst
                    data["Procotol"] = "IPv6"
                    data["len"] = len(corrupt_bytes(p))
                    data["info"] = p.summary()
                    return data
        else:
            # 处理以太网层协议
            if p.type in self.ETHER_DICT:
                data["time"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(timestamp)
                )
                data["Source"] = p.src
                data["Destination"] = p.dst
                data["Procotol"] = self.ETHER_DICT[p.type]
                data["len"] = len(corrupt_bytes(p))
                data["info"] = p.summary()
                return data
            else:
                data["time"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(timestamp)
                )
                data["Source"] = p.src
                data["Destination"] = p.dst
                data["Procotol"] = hex(p.type)
                data["len"] = len(corrupt_bytes(p))
                data["info"] = p.summary()
                return data

    def tcp_decode(self, p, ip):
        """
        解析TCP层协议数据包

        Args:
            p: 需要解析的数据包对象
            ip: IP层信息对象

        Returns:
            dict: 包含解析结果的字典,包含以下字段:
                time: 数据包的时间戳
                Source: 源IP:端口
                Destination: 目标IP:端口
                Protocol: 协议类型
                len: 数据包长度
                info: 数据包概要信息
        """
        data = dict()  # 存储解析结果
        tcp = p.getlayer(TCP)
        timestamp = float(p.time)
        data["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        data["Source"] = ip.src + ":" + str(ip.sport)  # 源IP和端口
        data["Destination"] = ip.dst + ":" + str(ip.dport)  # 目标IP和端口
        data["len"] = len(corrupt_bytes(p))  # 数据包长度
        data["info"] = p.summary()  # 数据包摘要
        # 根据端口查找协议
        if tcp.dport in self.PORT_DICT:
            data["Procotol"] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data["Procotol"] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data["Procotol"] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data["Procotol"] = self.TCP_DICT[tcp.sport]
        else:
            data["Procotol"] = "TCP"  # 默认协议为TCP
        return data

    def udp_decode(self, p, ip):
        """
        解析UDP层协议数据包

        Args:
            p: 需要解析的数据包对象
            ip: IP层信息对象

        Returns:
            dict: 包含解析结果的字典,包含以下字段:
                time: 数据包的时间戳
                Source: 源IP:端口
                Destination: 目标IP:端口
                Protocol: 协议类型
                len: 数据包长度
                info: 数据包概要信息
        """
        data = dict()  # 存储解析结果
        udp = p.getlayer(UDP)
        timestamp = float(p.time)
        data["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        data["Source"] = ip.src + ":" + str(ip.sport)  # 源IP和端口
        data["Destination"] = ip.dst + ":" + str(ip.dport)  # 目标IP和端口
        data["len"] = len(corrupt_bytes(p))  # 数据包长度
        data["info"] = p.summary()  # 数据包摘要
        # 根据端口查找协议
        if udp.dport in self.PORT_DICT:
            data["Procotol"] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data["Procotol"] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data["Procotol"] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data["Procotol"] = self.UDP_DICT[udp.sport]
        else:
            data["Procotol"] = "UDP"  # 默认协议为UDP
        return data
