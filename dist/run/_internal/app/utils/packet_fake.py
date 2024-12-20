# -*- coding:utf-8 -*-

import os


def get_ifaces():
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
    # 执行ifconfig命令获取网卡信息
    ifaces_list = os.popen("ifconfig").read().split("\n\n")
    # 过滤掉空行
    ifaces_list = [i for i in ifaces_list if i]
    iface_list = list()

    # 解析每个网卡的信息
    for ifaces in ifaces_list:
        # 获取网卡名称
        iface = ifaces.split("\n")[0].split()[0].strip()
        # 获取IP地址
        ip = ifaces.split("\n")[1].split()[1].split(":")[-1].strip()
        # 获取MAC地址
        mac = ifaces.split("\n")[0].split()[-1].strip()
        # 获取接收流量
        receive = (
            ifaces.split("\n")[-1].split()[1][1:]
            + ifaces.split("\n")[-1].split()[2][:-1]
        )
        # 获取发送流量
        send = (
            ifaces.split("\n")[-1].split()[-2][1:]
            + ifaces.split("\n")[-1].split()[-1][:-1]
        )
        # 将网卡信息添加到列表
        iface_list.append(
            {"iface": iface, "ip": ip, "mac": mac, "receive": receive, "send": send}
        )
    return iface_list
