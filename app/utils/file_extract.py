# -*- coding:utf-8 -*-

from .data_extract import web_data
from scapy.all import Raw
from collections import OrderedDict
import os
import re
import binascii


# web文件
def web_file(PCAPS, host_ip, folder):
    web_list = list()
    webdata = web_data(PCAPS, host_ip)
    for web in webdata:
        filename = ""
        raw_data_list = web["raw_data"].split(b"\r\n\r\n")
        data_list = web["data"].split("\r\n\r\n")
        switch = False
        start = False
        type = ""
        for raw_data, data in zip(raw_data_list, data_list):
            if start:
                file_name = (
                    type
                    + "_"
                    + web["ip_port"].split(":")[0]
                    + "_"
                    + web["ip_port"].split(":")[1]
                    + "_"
                    + filename
                )
                with open(folder + file_name, "wb") as f:
                    f.write(raw_data.strip())
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
            elif "POST" in data and "HTTP/1.1" in data:
                switch = True
                start = False
                type = "POST"
            else:
                pass
    return web_list


# 填充不符合规范的base64数据
def base64padding(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += "=" * missing_padding
    return data


# 所有二进制文件
def all_files(PCAPS, folder):
    file_header = dict()
    with open("./app/utils/protocol/FILES", "r", encoding="UTF-8") as f:
        lines = f.readlines()
    for line in lines:
        file_header[line.split(":")[0].strip()] = line.split(":")[1].strip()
    sessions = PCAPS.sessions()
    allfiles_dict = OrderedDict()
    allpayloads_dict = OrderedDict()
    for sess, ps in sessions.items():
        payload = b""
        for p in ps:
            if p.haslayer(Raw):
                payload += p[Raw].load
            if payload:
                allpayloads_dict[sess] = payload
    i = 0
    for sess, payload in allpayloads_dict.items():
        datas = payload.split(b"\r\n\r\n")
        for data in datas:
            d = binascii.hexlify(data.strip())
            for header, suffix in file_header.items():
                if d.startswith(header.encode("UTF-8")):
                    filename = str(i) + suffix
                    with open(folder + filename, "wb") as f:
                        f.write(binascii.unhexlify(d))
                    allfiles_dict[filename] = sess
                    i += 1
    return allfiles_dict
