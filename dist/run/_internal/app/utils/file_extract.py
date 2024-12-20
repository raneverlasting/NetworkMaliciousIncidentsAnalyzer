# -*- coding:utf-8 -*-

# 导入所需模块
from .data_extract import web_data
from scapy.all import Raw
from collections import OrderedDict
import os
import re
import binascii


def web_file(PCAPS, host_ip, folder):
    """
    从HTTP会话中提取文件
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
        folder: 保存文件的目录
    Returns:
        list: 包含提取文件信息的列表,每个元素包含IP端口、文件名和大小
    """
    web_list = list()  # 存储提取的文件信息
    webdata = web_data(PCAPS, host_ip)  # 获取HTTP会话数据
    
    # 遍历每个HTTP会话
    for web in webdata:
        filename = ""
        # 分割原始数据和解析后的数据
        raw_data_list = web["raw_data"].split(b"\r\n\r\n")
        data_list = web["data"].split("\r\n\r\n")
        switch = False  # 控制是否开始处理文件
        start = False  # 控制是否开始写入文件
        type = ""  # 请求类型(GET/POST)
        
        # 同时遍历原始数据和解析数据
        for raw_data, data in zip(raw_data_list, data_list):
            # 如果可以开始写入文件
            if start:
                # 构造文件名
                file_name = (
                    type
                    + "_"
                    + web["ip_port"].split(":")[0]
                    + "_"
                    + web["ip_port"].split(":")[1]
                    + "_"
                    + filename
                )
                # 写入文件
                with open(folder + file_name, "wb") as f:
                    f.write(raw_data.strip())
                # 记录文件信息
                web_list.append(
                    {
                        "ip_port": web["ip_port"].split(":")[0]
                        + ":"
                        + web["ip_port"].split(":")[1],
                        "filename": (folder + file_name),
                        "size": "%.2f" % (os.path.getsize(folder + file_name) / 1024.0),
                    }
                )
                start = False
                switch = False
                
            # 处理文件名和写入标志
            if switch:
                if "HTTP/1.1 200 OK" in data and "GET" not in data and type == "GET":
                    start = True
                    switch = False
                elif "filename" in data and type == "POST":
                    match = re.search(r'filename="(.*)?"', data)
                    filename = match.group(1) if match else ""
                    start = True
                    switch = False
                else:
                    filename = ""
                    switch = False
                    start = False
                    
            # 处理GET请求
            if "GET" in data and "HTTP/1.1" in data:
                try:
                    filename = data.split("\r\n")[0].split(" ")[1].split("/")[-1]
                    if re.match(r"^[A-Za-z0-9_]*?\.[A-Za-z0-9_]*?$", filename):
                        match = re.match(r"^[A-Za-z0-9_]*?\.[A-Za-z0-9_]*?$", filename)
                        filename = match.group() if match else ""
                        switch = True
                        start = False
                        type = "GET"
                except (IndexError, AttributeError):  # 指定可能的异常类型
                    pass
            # 处理POST请求
            elif "POST" in data and "HTTP/1.1" in data:
                switch = True
                start = False
                type = "POST"
            else:
                pass
    return web_list


def base64padding(data):
    """
    为Base64编码数据补全填充字符'='
    Args:
        data: Base64编码的数据
    Returns:
        str: 补全填充后的Base64数据
    """
    # 计算需要补充的填充字符数量
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += "=" * missing_padding
    return data


def all_files(PCAPS, folder):
    """
    从数据包中提取所有二进制文件
    Args:
        PCAPS: 数据包列表
        folder: 保存文件的目录
    Returns:
        OrderedDict: 文件名和对应会话ID的映射
    """
    # 读取文件头特征码配置
    file_header = dict()
    base_dir = os.path.abspath(os.path.dirname(__file__))
    files_path = os.path.join(base_dir, "protocol", "FILES")
    with open(files_path, "r", encoding="UTF-8") as f:
        lines = f.readlines()
    for line in lines:
        file_header[line.split(":")[0].strip()] = line.split(":")[1].strip()
        
    # 获取所有会话
    sessions = PCAPS.sessions()
    allfiles_dict = OrderedDict()  # 存储文件名和会话ID的映射
    allpayloads_dict = OrderedDict()  # 存储会话ID和负载数据的映射
    
    # 提取每个会话的负载数据
    for sess, ps in sessions.items():
        payload = b""
        for p in ps:
            if p.haslayer(Raw):
                payload += p[Raw].load
            if payload:
                allpayloads_dict[sess] = payload
                
    # 处理每个会话的负载数据
    i = 0
    for sess, payload in allpayloads_dict.items():
        datas = payload.split(b"\r\n\r\n")
        for data in datas:
            d = binascii.hexlify(data.strip())
            # 根据文件头特征码识别文件类型
            for header, suffix in file_header.items():
                if d.startswith(header.encode("UTF-8")):
                    filename = str(i) + suffix
                    # 写入文件
                    with open(folder + filename, "wb") as f:
                        f.write(binascii.unhexlify(d))
                    allfiles_dict[filename] = sess
                    i += 1
    return allfiles_dict
