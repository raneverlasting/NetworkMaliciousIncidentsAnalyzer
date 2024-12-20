# -*- coding:utf-8 -*-

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
import time
import re
import collections
import binascii
import os
from .data_extract import web_data, telnet_ftp_data


# 根据可疑端口判断是否有木马病毒
def port_warning(PCAPS, host_ip):
    """
    检测数据包中是否存在可疑端口,判断是否有木马病毒
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
    Returns:
        portwarn_list: 可疑端口警告列表
    """
    # 读取可疑端口配置文件
    base_dir = os.path.abspath(os.path.dirname(__file__))
    warn_path = os.path.join(base_dir, "protocol", "WARN")
    with open(warn_path, "r", encoding="UTF-8") as f:
        warns = f.readlines()
    WARN_DICT = dict()
    for warn in warns:
        warn = warn.strip()
        WARN_DICT[int(warn.split(":")[0])] = warn.split(":")[1]
    # 迭代数据包
    portwarn_list = list()
    for pcap in PCAPS:
        if pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            sport = tcp.sport
            dport = tcp.dport
            # 检查源IP是否为主机IP
            if src == host_ip:
                ip = dst
                if sport in WARN_DICT:
                    portwarn_list.append(
                        {
                            "ip_port": ip + ":" + str(sport),
                            "warn": WARN_DICT[sport],
                            "time": time.strftime(
                                "%Y-%m-%d %H:%M:%S", time.localtime(pcap.time)
                            ),
                            "data": pcap.summary(),
                        }
                    )
                elif dport in WARN_DICT:
                    portwarn_list.append(
                        {
                            "ip_port": ip + ":" + str(dport),
                            "warn": WARN_DICT[dport],
                            "time": time.strftime(
                                "%Y-%m-%d %H:%M:%S", time.localtime(pcap.time)
                            ),
                            "data": pcap.summary(),
                        }
                    )
                else:
                    pass
            # 检查目标IP是否为主机IP
            elif dst == host_ip:
                ip = src
                if sport in WARN_DICT:
                    portwarn_list.append(
                        {
                            "ip_port": ip + ":" + str(sport),
                            "warn": WARN_DICT[sport],
                            "time": time.strftime(
                                "%Y-%m-%d %H:%M:%S", time.localtime(pcap.time)
                            ),
                            "data": pcap.summary(),
                        }
                    )
                elif dport in WARN_DICT:
                    portwarn_list.append(
                        {
                            "ip_port": ip + ":" + str(dport),
                            "warn": WARN_DICT[dport],
                            "time": time.strftime(
                                "%Y-%m-%d %H:%M:%S", time.localtime(pcap.time)
                            ),
                            "data": pcap.summary(),
                        }
                    )
                else:
                    pass
            else:
                pass
    return portwarn_list


# 根据WEB内容来匹配常见WEB攻击,SQL注入，XSS，暴力破解，目录遍历，任意文件下载，木马
def web_warning(PCAPS, host_ip):
    """
    检测Web攻击,包括SQL注入、XSS、暴力破解、目录遍历、任意文件下载、木马等
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
    Returns:
        webwarn_list: Web攻击警告列表
    """
    # 读取HTTP攻击特征配置文件
    base_dir = os.path.abspath(os.path.dirname(__file__))
    http_attack_path = os.path.join(base_dir, "warning", "HTTP_ATTACK")
    with open(http_attack_path, "r", encoding="UTF-8") as f:
        attacks = f.readlines()
    ATTACK_DICT = dict()
    for attack in attacks:
        attack = attack.strip()
        ATTACK_DICT[attack.split(" : ")[0]] = attack.split(" : ")[1]
    webdata = web_data(PCAPS, host_ip)
    webwarn_list = list()
    webbur_list = list()
    # 定义用户名、密码、Tomcat认证的正则表达式
    web_patternu = re.compile(r"((txtUid|username|user|name)=(.*?))&", re.I)
    web_patternp = re.compile(r"((txtPwd|password|pwd|passwd)=(.*?))&", re.I)
    tomcat_pattern = re.compile(r"Authorization: Basic(.*)")
    for web in webdata:
        data = web["data"]
        # 检测HTTP暴力破解
        username = web_patternu.findall(data)
        password = web_patternp.findall(data)
        tomcat = tomcat_pattern.findall(data)
        if username or password or tomcat:
            webbur_list.append(web["ip_port"].split(":")[0])
        # 检测其他Web攻击
        for pattn, attk in ATTACK_DICT.items():  # 特征码和攻击名称
            if pattn.upper() in data.upper():
                webwarn_list.append(
                    {
                        "ip_port": web["ip_port"].split(":")[0]
                        + ":"
                        + web["ip_port"].split(":")[1],
                        "warn": attk,
                        "time": pattn,
                        "data": data,
                    }
                )
    # 统计HTTP暴力破解
    ip_count = collections.Counter(webbur_list)
    warn_ip = {k: y for k, y in ip_count.items() if y > 10}
    for ip, count in warn_ip.items():
        webwarn_list.append(
            {"ip_port": ip, "warn": "HTTP暴力破解", "time": str(count), "data": None}
        )
    return webwarn_list


# 根据FTP登录失败次数，判断FTP暴力破解攻击,登录次数打大于10次算暴力破解
def ftp_warning(PCAPS, host_ip):
    """
    检测FTP暴力破解攻击
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
    Returns:
        ftpwarn_list: FTP攻击警告列表
    """
    ftpdata = telnet_ftp_data(PCAPS, host_ip, 21)
    ftpwarn_list = list()
    ftp503_list = list()
    # 检测登录失败的情况
    for ftp in ftpdata:
        if "530 Not logged in" in ftp["data"]:
            ftp503_list.append(ftp["ip_port"].split(":")[0])
    # 统计登录失败次数
    ip_count = collections.Counter(ftp503_list)
    warn_ip = {k: y for k, y in ip_count.items() if y > 10}
    for ip, count in warn_ip.items():
        ftpwarn_list.append(
            {"ip_port": ip, "warn": "FTP暴力破解", "time": str(count), "data": None}
        )
    return ftpwarn_list


# 根据Telnet登录失败次数，判断Telnet暴力破解攻击,登录次数大于10次算暴力破解
def telnet_warning(PCAPS, host_ip):
    """
    检测Telnet暴力破解攻击
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
    Returns:
        telnetwarn_list: Telnet攻击警告列表
    """
    telnetdata = telnet_ftp_data(PCAPS, host_ip, 23)
    telnetwarn_list = list()
    telnetfail_list = list()
    # 检测登录失败的情况
    for telnet in telnetdata:
        if b"4c6f67696e204661696c6564" in binascii.hexlify(
            telnet["data"]
        ) or b"6c6f67696e206661696c6564" in binascii.hexlify(telnet["data"]):
            telnetfail_list.append(telnet["ip_port"].split(":")[0])
    # 统计登录失败次数
    ip_count = collections.Counter(telnetfail_list)
    warn_ip = {k: y for k, y in ip_count.items() if y > 10}
    for ip, count in warn_ip.items():
        telnetwarn_list.append(
            {"ip_port": ip, "warn": "Telnet暴力破解", "time": str(count), "data": None}
        )
    return telnetwarn_list


# 检测ARP欺骗攻击
def arp_warning(PCAPS):
    """
    检测ARP欺骗攻击
    Args:
        PCAPS: 数据包列表
    Returns:
        arpwarn_list: ARP攻击警告列表
    """
    arpwarn_list = list()
    arp_list = list()
    # 收集ARP响应包
    for pcap in PCAPS:
        if pcap.haslayer(ARP) and pcap.getlayer(ARP).op == 2:
            arp_list.append({"src": pcap.src, "summary": pcap.summary()})
    # 按源MAC地址分组
    arpsrc_dict = dict()
    for arp in arp_list:
        if arp["src"] in arpsrc_dict:
            arpsrc_dict[arp["src"]].append(arp["summary"])
        else:
            arpsrc_dict[arp["src"]] = [arp["summary"]]
    # 检测ARP欺骗
    for src, summary in arpsrc_dict.items():
        # 若当前src下只有1个访问请求，则判定为正常ARP访问
        if len(set(summary)) == 1:
            pass
        # 若当前src下存在多个访问请求，则判定为ARP欺骗
        else:
            arpwarn_list.append(
                {
                    "ip_port": src,
                    "warn": "ARP欺骗",
                    "time": set([s.split()[-1] for s in summary]),
                    "data": None,
                }
            )
    return arpwarn_list


def exception_warning(PCAPS, host_ip):
    """
    获取系统所有网卡的信息
    Returns:
        list: 包含每个网卡信息的字典列表,每个字典包含:
            iface: 网卡名称
            ip: IP地址
            mac: MAC地址
            receive: 接收流量
            send: 发送流量
    """
    warn_list = list()
    port_list = port_warning(PCAPS, host_ip)
    arp_list = arp_warning(PCAPS)
    web_list = web_warning(PCAPS, host_ip)
    telnet_list = telnet_warning(PCAPS, host_ip)
    ftp_list = ftp_warning(PCAPS, host_ip)
    if web_list:
        warn_list.extend(web_list)
    if telnet_list:
        warn_list.extend(telnet_list)
    if ftp_list:
        warn_list.extend(ftp_list)
    if port_list:
        warn_list.append(port_list)
    if arp_list:
        warn_list.append(arp_list)
    return warn_list
