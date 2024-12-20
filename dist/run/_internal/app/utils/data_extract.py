# -*- coding:utf-8 -*-

# 导入所需的库
from scapy.all import corrupt_bytes, Raw  # 用于处理数据包
from scapy.layers.inet import IP, TCP  # 用于处理IP和TCP层
from scapy.layers.l2 import Ether  # 用于处理以太网层
from collections import OrderedDict  # 用于保持字典的插入顺序
import re  # 用于正则表达式匹配
import time  # 用于时间处理
import os  # 用于文件和路径操作
import binascii  # 用于二进制和ASCII转换
import base64  # 用于base64编解码


# 提取HTTP协议(80,8080端口)的Web连接数据
def web_data(PCAPS, host_ip):
    """
    提取HTTP协议的Web连接数据
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
    Returns:
        ip_port_data_list: 包含HTTP数据的列表,每个元素为字典,包含数据ID、IP端口、数据内容等信息
    """
    ip_port_id_list = list()  # 存储IP端口和数据包ID的列表
    id = -1
    # 遍历数据包
    for pcap in PCAPS:
        id += 1
        # 检查是否包含TCP层和Raw层
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            src = pcap.getlayer(IP).src  # 源IP
            dst = pcap.getlayer(IP).dst  # 目的IP
            sport = pcap.sport  # 源端口
            dport = pcap.dport  # 目的端口
            # 处理源端口为80或8080的情况
            if sport == 80 or sport == 8080:
                port = dport
                if src == host_ip:  # 源IP是主机IP
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "HTTP", "id": id}
                    )
                elif dst == host_ip:  # 目的IP是主机IP
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "HTTP", "id": id}
                    )
                else:
                    pass
            # 处理目的端口为80或8080的情况
            elif dport == 80 or dport == 8080:
                port = sport
                if src == host_ip:  # 源IP是主机IP
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "HTTP", "id": id}
                    )
                elif dst == host_ip:  # 目的IP是主机IP
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "HTTP", "id": id}
                    )
                else:
                    pass
            else:
                pass

    # 记录每个使用HTTP协议的ip:port下的数据包id(即PCAPS[id])
    # 格式: {'192.134.13.234:232':[2,3,4,5],'192.134.13.234:236':[4,3,2,4,3]}
    ip_port_ids_dict = OrderedDict()  # 使用有序字典保持顺序
    for ip_port_id in ip_port_id_list:
        if ip_port_id["ip_port"] in ip_port_ids_dict:
            ip_port_ids_dict[ip_port_id["ip_port"]].append(
                ip_port_id["id"]
            )  # 已存在的IP端口,添加数据包ID
        else:
            ip_port_ids_dict[ip_port_id["ip_port"]] = [
                ip_port_id["id"]
            ]  # 新的IP端口,创建数据包ID列表

    # 处理每个ip:port的数据
    ip_port_data_list = list()  # 存储最终的数据列表
    data_id = 0
    for ip_port, load_list in ip_port_ids_dict.items():
        data_id += 1
        raw_data = b"".join([PCAPS[i].load for i in load_list])  # 合并原始数据
        # 智能判断编码,优先使用GBK解码
        tmp_data = raw_data.decode("UTF-8", "ignore")
        if ("gbk" in tmp_data) or ("GBK" in tmp_data):
            data = raw_data.decode("GBK", "ignore")
        else:
            data = tmp_data
        ip_port_data_list.append(
            {
                "data_id": data_id,  # 数据ID
                "ip_port": ip_port,  # IP和端口
                "data": data,  # 解码后的数据
                "raw_data": raw_data,  # 原始数据
                "lens": "%.3f"  # 数据长度(KB)
                % (sum([len(corrupt_bytes(PCAPS[i])) for i in load_list]) / 1024.0),
            }
        )
    return ip_port_data_list


# 提取邮件协议数据:
# POP3(110端口)
# IMAP(143端口)
# SMTP(25端口)
def mail_data(PCAPS, host_ip):
    """
    提取邮件协议数据
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
    Returns:
        ip_port_data_list: 包含邮件数据的列表,每个元素为字典,包含数据ID、IP端口、数据内容等信息
    """
    ip_port_id_list = list()  # 存储IP端口和数据包ID的列表
    id = 0
    # 遍历数据包
    for pcap in PCAPS:
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            src = pcap.getlayer(IP).src  # 源IP
            dst = pcap.getlayer(IP).dst  # 目的IP
            sport = pcap.sport  # 源端口
            dport = pcap.dport  # 目的端口
            # 处理POP3协议(110端口)
            if sport == 110:
                port = dport
                if src == host_ip:  # 源IP是主机IP
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "POP3", "id": id}
                    )
                elif dst == host_ip:  # 目的IP是主机IP
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "POP3", "id": id}
                    )
                else:
                    pass
            # 处理IMAP协议(143端口)
            elif sport == 143:
                port = dport
                if src == host_ip:  # 源IP是主机IP
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "IMAP", "id": id}
                    )
                elif dst == host_ip:  # 目的IP是主机IP
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "IMAP", "id": id}
                    )
                else:
                    pass
            # 处理SMTP协议(25端口)
            elif sport == 25:
                port = dport
                if src == host_ip:  # 源IP是主机IP
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "SMTP", "id": id}
                    )
                elif dst == host_ip:  # 目的IP是主机IP
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "SMTP", "id": id}
                    )
                else:
                    pass
            elif dport == 110:
                port = sport
                if src == host_ip:  # 源IP是主机IP
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "POP3", "id": id}
                    )
                elif dst == host_ip:  # 目的IP是主机IP
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "POP3", "id": id}
                    )
                else:
                    pass
            elif dport == 143:
                port = sport
                if src == host_ip:  # 源IP是主机IP
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "IMAP", "id": id}
                    )
                elif dst == host_ip:  # 目的IP是主机IP
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "IMAP", "id": id}
                    )
                else:
                    pass
            elif dport == 25:
                port = sport
                if src == host_ip:  # 源IP是主机IP
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "SMTP", "id": id}
                    )
                elif dst == host_ip:  # 目的IP是主机IP
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + "SMTP", "id": id}
                    )
                else:
                    pass
            else:
                pass
        id += 1

    # 记录每个使用邮件协议的ip:port下的数据包id
    # 格式: {'192.134.13.234:232':[2,3,4,5],'192.134.13.234:232':[4,3,2,4,3]}
    ip_port_ids_dict = OrderedDict()  # 使用有序字典保持顺序
    for ip_port_id in ip_port_id_list:
        if ip_port_id["ip_port"] in ip_port_ids_dict:
            ip_port_ids_dict[ip_port_id["ip_port"]].append(
                ip_port_id["id"]
            )  # 已存在的IP端口,添加数据包ID
        else:
            ip_port_ids_dict[ip_port_id["ip_port"]] = [
                ip_port_id["id"]
            ]  # 新的IP端口,创建数据包ID列表

    # 处理每个ip:port的数据
    ip_port_data_list = list()  # 存储最终的数据列表
    data_id = 0
    for ip_port, load_list in ip_port_ids_dict.items():
        data_id += 1
        raw_data = b"".join([PCAPS[i].load for i in load_list])  # 合并原始数据
        # 根据协议类型解析数据
        if "SMTP" in ip_port:
            parse_data = smtp_parse(raw_data)  # 解析SMTP协议数据
        elif "POP3" in ip_port:
            parse_data = pop3_parse(raw_data)  # 解析POP3协议数据
        elif "IMAP" in ip_port:
            parse_data = imap_parse(raw_data)  # 解析IMAP协议数据
        else:
            parse_data = None
        # 使用UTF-8解码
        data = raw_data.decode("UTF-8", "ignore")
        ip_port_data_list.append(
            {
                "data_id": data_id,  # 数据ID
                "ip_port": ip_port,  # IP和端口
                "data": data,  # 解码后的数据
                "raw_data": raw_data,  # 原始数据
                "parse_data": parse_data,  # 解析后的数据
                "lens": "%.3f"  # 数据长度(KB)
                % (sum([len(corrupt_bytes(PCAPS[i])) for i in load_list]) / 1024.0),
            }
        )
    return ip_port_data_list


# 解析SMTP协议数据,提取邮件相关字段
def smtp_parse(raw_data):
    """
    解析SMTP协议数据
    Args:
        raw_data: 原始数据
    Returns:
        parse_data: 解析后的数据字典,包含用户名、密码、邮件日期、发件人、收件人等信息
    """
    data = raw_data.decode("UTF-8", "ignore")
    # 定义各字段的正则表达式
    mailuser_p = re.compile(r"dXNlcm5hbWU6\r\n(.*?)\r\n", re.S)  # 用户名
    mailpasswd_p = re.compile(r"UGFzc3dvcmQ6\r\n(.*?)\r\n", re.S)  # 密码
    maildate_p = re.compile(r"Date:(.*?)\r\n", re.S)  # 日期
    mailfrom_p = re.compile(r"RCPT TO:(.*?)\r\n", re.S)  # 发件人
    mailto_p = re.compile(r"To:(.*?)\r\n", re.S)  # 收件人
    mailcc_p = re.compile(r"Cc:(.*?)\r\nSubject", re.S)  # 抄送
    mailsubject_p = re.compile(r"Subject:(.*?)\r\n", re.S)  # 主题
    mailmessageid_p = re.compile(r"Message-ID:(.*?)\r\n", re.S)  # 消息ID
    charset_p = re.compile(r'charset="(.*?)"', re.S)  # 字符集
    mailcontent_p = re.compile(
        r"Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------=", re.S
    )  # 邮件内容

    # 提取各字段数据
    username_ = mailuser_p.search(data)
    password_ = mailpasswd_p.search(data)
    maildate_ = maildate_p.search(data)
    mailfrom_ = mailfrom_p.search(data)
    mailto_ = mailto_p.search(data)
    mailcc_ = mailcc_p.search(data)
    mailsubject_ = mailsubject_p.search(data)
    mailmessageid_ = mailmessageid_p.search(data)
    charset_ = charset_p.search(data)
    mailcontent_ = mailcontent_p.search(data)
    charset = charset_.group(1) if charset_ else "UTF-8"  # 获取字符集,默认UTF-8
    username = (
        base64.b64decode(base64padding(username_.group(1))).decode("UTF-8")
        if username_
        else None
    )  # 解码用户名
    password = (
        base64.b64decode(base64padding(password_.group(1))).decode("UTF-8")
        if password_
        else None
    )  # 解码密码
    maildate = maildate_.group(1).strip() if maildate_ else None  # 获取日期
    mailfrom = mailfrom_.group(1).strip() if mailfrom_ else None  # 获取发件人
    mailto = mailto_.group(1).strip() if mailto_ else None  # 获取收件人
    mailcc = mailcc_.group(1).strip() if mailcc_ else None  # 获取抄送
    mailmessageid = (
        mailmessageid_.group(1).strip() if mailmessageid_ else None
    )  # 获取消息ID
    if mailsubject_:
        mailsubject_ = mailsubject_.group(1).strip()
        if mailsubject_ and "=?" in mailsubject_:  # 处理编码的主题
            mailsubject_ = mailsubject_.split("?")
            mailsubject = base64.b64decode(base64padding(mailsubject_[3])).decode(
                mailsubject_[1], "ignore"
            )
        else:
            mailsubject = mailsubject_
    else:
        mailsubject = None
    if mailcontent_:  # 处理邮件内容
        mailcontent_ = mailcontent_.group(1).strip().replace("\r\n", "")
        mailcontent = base64.b64decode(base64padding(mailcontent_)).decode(
            charset, "ignore"
        )
    else:
        mailcontent = None
    attachs_dict = findmail_attachs(raw_data)  # 提取附件
    parse_data = {
        "username": username,  # 用户名
        "password": password,  # 密码
        "maildate": maildate,  # 日期
        "mailfrom": mailfrom,  # 发件人
        "mailto": mailto,  # 收件人
        "mailcc": mailcc,  # 抄送
        "mailsubject": mailsubject,  # 主题
        "mailmessageid": mailmessageid,  # 消息ID
        "mailcontent": mailcontent,  # 内容
        "attachs_dict": attachs_dict,  # 附件
    }
    return parse_data


# 填充不规范的base64数据
def base64padding(data):
    """
    填充不规范的base64数据
    Args:
        data: 原始base64数据
    Returns:
        填充后的base64数据
    """
    missing_padding = 4 - len(data) % 4  # 计算需要填充的=号个数
    if missing_padding:
        data += "=" * missing_padding  # 填充=号
    return data


# 提取邮件中的所有附件
def findmail_attachs(raw_data):
    """
    提取邮件中的所有附件
    Args:
        raw_data: 原始数据
    Returns:
        attachs_dict: 附件字典,key为文件名,value为文件内容
    """
    filename_p = re.compile(r'filename="(.*?)"', re.S)  # 文件名正则表达式
    attachs_dict = dict()  # 存储附件的字典
    charset = "UTF-8"  # 默认字符集
    data_list = raw_data.decode("UTF-8", "ignore").split("\r\n\r\n")  # 分割数据
    filename = "unknown"  # 默认文件名
    switch = False  # 切换标志
    for data in data_list:
        if switch:  # 如果是附件内容
            if data:
                data = data.strip().replace("\r\n", "")  # 清理数据
                filedata = base64.b64decode(base64padding(data))  # 解码数据
            else:
                filedata = None
            if filedata:
                try:
                    filedata = filedata.decode(charset)  # 尝试解码
                except Exception:
                    pass
            attachs_dict[filename] = filedata  # 存储附件
            switch = False
        if "filename" in data:  # 如果包含文件名
            switch = True
            filename_ = filename_p.search(data)
            if filename_:
                filename_ = filename_.group(1).strip()
                if filename_ and "=?" in filename_:  # 处理编码的文件名
                    filename_ = filename_.split("?")
                    charset = filename_[1]  # 获取字符集
                    filename = base64.b64decode(base64padding(filename_[3])).decode(
                        charset, "ignore"
                    )
                else:
                    filename = filename_
            else:
                filename = "unknow"
    return attachs_dict


# 解析POP3协议数据,提取邮件相关字段
def pop3_parse(raw_data):
    """
    解析POP3协议数据
    Args:
        raw_data: 原始数据
    Returns:
        parse_data: 解析后的数据字典,包含用户名、密码、邮件日期、发件人、收件人等信息
    """
    data = raw_data.decode("UTF-8", "ignore")
    # 定义各字段的正则表达式
    mailuser_p = re.compile(r"USER(.*?)\r\n", re.S)  # 用户名
    mailpasswd_p = re.compile(r"PASS(.*?)\r\n", re.S)  # 密码
    maildate_p = re.compile(r"Date:(.*?)\r\n", re.S)  # 日期
    mailfrom_p = re.compile(r"From:(.*?)\r\n", re.S)  # 发件人
    mailto_p = re.compile(r"To:(.*?)\r\n", re.S)  # 收件人
    mailcc_p = re.compile(r"Cc:(.*?)\r\nSubject", re.S)  # 抄送
    mailsubject_p = re.compile(r"Subject:(.*?)\r\n", re.S)  # 主题
    mailmessageid_p = re.compile(r"Message-ID:(.*?)\r\n", re.S)  # 消息ID
    charset_p = re.compile(r'charset="(.*?)"', re.S)  # 字符集
    mailcontent_p = re.compile(
        r"Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------=", re.S
    )  # 邮件内容

    # 提取各字段数据
    username_ = mailuser_p.search(data)
    password_ = mailpasswd_p.search(data)
    maildate_ = maildate_p.findall(data)
    mailfrom_ = mailfrom_p.findall(data)
    mailto_ = mailto_p.findall(data)
    mailcc_ = mailcc_p.search(data)
    mailsubject_ = mailsubject_p.findall(data)
    mailmessageid_ = mailmessageid_p.search(data)
    charset_ = charset_p.search(data)
    mailcontent_ = mailcontent_p.search(data)
    charset = charset_.group(1) if charset_ else "UTF-8"  # 获取字符集,默认UTF-8
    username = username_.group(1).strip() if username_ else None  # 获取用户名
    password = password_.group(1).strip() if password_ else None  # 获取密码
    maildate = maildate_[-1].strip() if maildate_ else None  # 获取日期
    mailfrom_ = mailfrom_[-1].strip() if mailfrom_ else None  # 获取发件人
    if mailfrom_ and "=?" in mailfrom_:  # 处理编码的发件人
        mailfrom_ = mailfrom_.split("?")
        mailfrom_address = mailfrom_[-1].split()[-1]  # 获取邮件地址
        mailfrom_name = base64.b64decode(base64padding(mailfrom_[3])).decode(
            mailfrom_[1], "ignore"
        )  # 解码发件人名称
        mailfrom = "{}".format(mailfrom_name) + " " + mailfrom_address
    else:
        mailfrom = mailfrom_
    mailto_ = mailto_[-1].strip() if mailto_ else None  # 获取收件人
    if mailto_ and "=?" in mailto_:  # 处理编码的收件人
        mailto_ = mailto_.split("?")
        mailto_address = mailto_[-1].split()[-1]  # 获取邮件地址
        mailto_name = base64.b64decode(base64padding(mailto_[3])).decode(
            mailto_[1], "ignore"
        )  # 解码收件人名称
        mailto = "{}".format(mailto_name) + " " + mailto_address
    else:
        mailto = mailto_
    mailcc = mailcc_.group(1).strip() if mailcc_ else None  # 获取抄送
    mailmessageid = (
        mailmessageid_.group(1).strip() if mailmessageid_ else None
    )  # 获取消息ID
    if mailsubject_:  # 处理主题
        mailsubject_ = mailsubject_[-1].strip()
        if mailsubject_ and "=?" in mailsubject_:  # 处理编码的主题
            mailsubject_ = mailsubject_.split("?")
            mailsubject = base64.b64decode(base64padding(mailsubject_[3])).decode(
                mailsubject_[1], "ignore"
            )
        else:
            mailsubject = mailsubject_
    else:
        mailsubject = None
    if mailcontent_:  # 处理邮件内容
        mailcontent_ = mailcontent_.group(1).strip().replace("\r\n", "")
        mailcontent = base64.b64decode(base64padding(mailcontent_)).decode(
            charset, "ignore"
        )
    else:
        mailcontent = None
    attachs_dict = findmail_attachs(raw_data)  # 提取附件
    parse_data = {
        "username": username,  # 用户名
        "password": password,  # 密码
        "maildate": maildate,  # 日期
        "mailfrom": mailfrom,  # 发件人
        "mailto": mailto,  # 收件人
        "mailcc": mailcc,  # 抄送
        "mailsubject": mailsubject,  # 主题
        "mailmessageid": mailmessageid,  # 消息ID
        "mailcontent": mailcontent,  # 内容
        "attachs_dict": attachs_dict,  # 附件
    }
    return parse_data


# 解析IMAP协议数据,提取邮件相关字段
def imap_parse(raw_data):
    """
    解析IMAP协议数据
    Args:
        raw_data: 原始数据
    Returns:
        parse_data: 解析后的数据字典,包含用户名、密码、邮件日期、发件人、收件人等信息
    """
    data = raw_data.decode("UTF-8", "ignore")
    # 定义各字段的正则表达式
    mailuser_pwd_p = re.compile(r"LOGIN(.*?)\r\n", re.S)  # 用户名和密码
    maildate_p = re.compile(r"Date:(.*?)\r\n", re.S)  # 日期
    mailfrom_p = re.compile(r"From:(.*?)\r\n", re.S)  # 发件人
    mailto_p = re.compile(r"To:(.*?)\r\n", re.S)  # 收件人
    mailcc_p = re.compile(r"Cc:(.*?)\r\nSubject", re.S)  # 抄送
    mailsubject_p = re.compile(r"Subject:(.*?)\r\n", re.S)  # 主题
    mailmessageid_p = re.compile(r"Message-ID:(.*?)\r\n", re.S)  # 消息ID
    charset_p = re.compile(r'charset="(.*?)"', re.S)  # 字符集
    mailcontent_p = re.compile(
        r"Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------=", re.S
    )  # 邮件内容

    # 提取各字段数据
    username_pwd_ = mailuser_pwd_p.search(data)
    maildate_ = maildate_p.findall(data)
    mailfrom_ = mailfrom_p.findall(data)
    mailto_ = mailto_p.findall(data)
    mailcc_ = mailcc_p.search(data)
    mailsubject_ = mailsubject_p.findall(data)
    mailmessageid_ = mailmessageid_p.search(data)
    charset_ = charset_p.search(data)
    mailcontent_ = mailcontent_p.search(data)
    charset = charset_.group(1) if charset_ else "UTF-8"  # 获取字符集,默认UTF-8
    username_pwd = (
        username_pwd_.group(1).strip() if username_pwd_ else None
    )  # 获取用户名和密码
    if username_pwd:  # 分离用户名和密码
        username = username_pwd.split()[0]  # 用户名
        password = username_pwd.split()[-1][1:-1]  # 密码
    else:
        username = None
    charset = charset_.group(1) if charset_ else "UTF-8"
    username_pwd = username_pwd_.group(1).strip() if username_pwd_ else None
    if username_pwd:
        username = username_pwd.split()[0]
        password = username_pwd.split()[-1][1:-1]
    else:
        username = None
        password = None
    maildate = maildate_[-1].strip() if maildate_ else None
    mailfrom_ = mailfrom_[-1].strip() if mailfrom_ else None
    if mailfrom_ and ("=?" in mailfrom_):
        mailfrom_ = mailfrom_.split("?")
        mailfrom_address = mailfrom_[-1].split()[-1]
        mailfrom_name = base64.b64decode(base64padding(mailfrom_[3])).decode(
            mailfrom_[1], "ignore"
        )
        mailfrom = "{}".format(mailfrom_name) + " " + mailfrom_address
    else:
        mailfrom = mailfrom_
    mailto_ = mailto_[-1].strip() if mailto_ else None
    if mailto_ and "=?" in mailto_:
        mailto_ = mailto_.split("?")
        mailto_address = mailto_[-1].split()[-1]
        mailto_name = base64.b64decode(base64padding(mailto_[3])).decode(
            mailto_[1], "ignore"
        )
        mailto = "{}".format(mailto_name) + " " + mailto_address
    else:
        mailto = mailto_
    mailcc = mailcc_.group(1).strip() if mailcc_ else None
    mailmessageid = mailmessageid_.group(1).strip() if mailmessageid_ else None
    if mailsubject_:
        mailsubject_ = mailsubject_[-1].strip()
        if mailsubject_ and "=?" in mailsubject_:
            mailsubject_ = mailsubject_.split("?")
            mailsubject = base64.b64decode(base64padding(mailsubject_[3])).decode(
                mailsubject_[1], "ignore"
            )
        else:
            mailsubject = mailsubject_
    else:
        mailsubject = None
    if mailcontent_:
        mailcontent_ = mailcontent_.group(1).strip().replace("\r\n", "")
        mailcontent = base64.b64decode(base64padding(mailcontent_)).decode(
            charset, "ignore"
        )
    else:
        mailcontent = None
    attachs_dict = findmail_attachs(raw_data)
    parse_data = {
        "username": username,
        "password": password,
        "maildate": maildate,
        "mailfrom": mailfrom,
        "mailto": mailto,
        "mailcc": mailcc,
        "mailsubject": mailsubject,
        "mailmessageid": mailmessageid,
        "mailcontent": mailcontent,
        "attachs_dict": attachs_dict,
    }
    return parse_data


# 提取Telnet(23端口)和FTP(21端口)协议数据
def telnet_ftp_data(PCAPS, host_ip, tfport):
    """
    提取Telnet和FTP协议数据
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
        tfport: 端口号(21或23)
    Returns:
        ip_port_data_list: 包含Telnet/FTP数据的列表
    """
    if tfport == 21:
        proto = "FTP"
    elif tfport == 23:
        proto = "Telnet"
    else:
        proto = "Other"
    ip_port_id_list = list()
    id = 0
    # 遍历数据包
    for pcap in PCAPS:
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            sport = pcap.sport
            dport = pcap.dport
            if sport == tfport:
                port = dport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + proto, "id": id}
                    )
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + proto, "id": id}
                    )
                else:
                    pass
            elif dport == tfport:
                port = sport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + proto, "id": id}
                    )
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append(
                        {"ip_port": ip + ":" + str(port) + ":" + proto, "id": id}
                    )
                else:
                    pass
            else:
                pass
        id += 1

    # 记录每个使用Telnet/FTP协议的ip:port下的数据包id
    # 格式: {'192.134.13.234:232':[2,3,4,5],'192.134.13.234:232':[4,3,2,4,3]}
    ip_port_ids_dict = OrderedDict()
    for ip_port_id in ip_port_id_list:
        if ip_port_id["ip_port"] in ip_port_ids_dict:
            ip_port_ids_dict[ip_port_id["ip_port"]].append(ip_port_id["id"])
        else:
            ip_port_ids_dict[ip_port_id["ip_port"]] = [ip_port_id["id"]]

    ip_port_data_list = list()
    data_id = 0
    for ip_port, load_list in ip_port_ids_dict.items():
        data_id += 1
        raw_data = b"".join([PCAPS[i].load for i in load_list])
        # 使用UTF-8解码
        data = raw_data.decode("UTF-8", "ignore")
        ip_port_data_list.append(
            {
                "data_id": data_id,
                "ip_port": ip_port,
                "data": data,
                "raw_data": raw_data,
                "lens": "%.3f"
                % (sum([len(corrupt_bytes(PCAPS[i])) for i in load_list]) / 1024.0),
            }
        )
    return ip_port_data_list


# 提取客户端信息
def client_info(PCAPS):
    """
    提取数据包中的客户端信息
    Args:
        PCAPS: 数据包列表
    Returns:
        clientinfo_list: 包含客户端信息的列表,每个元素为字典,包含会话、MAC地址、IP地址、客户端类型等信息
    """
    # 获取客户端特征文件路径
    base_dir = os.path.abspath(os.path.dirname(__file__))
    client_info_path = os.path.join(base_dir, "warning", "CLIENT_INFO")
    # 读取客户端特征
    with open(client_info_path, "r", encoding="UTF-8") as f:
        lines = f.readlines()
    client_patterns = [i.strip() for i in lines]  # 客户端特征模式列表

    clientinfo_list = list()  # 存储客户端信息的列表
    allpayloads_dict = OrderedDict()  # 存储所有数据包载荷的字典
    sessions = PCAPS.sessions()  # 获取所有会话
    # 初始化变量
    ip_src = "unknown"  # 源IP
    ip_dst = "unknown"  # 目的IP
    ether_src = None  # 源MAC
    ether_dst = None  # 目的MAC

    # 遍历所有会话和载荷
    for sess, payload in allpayloads_dict.items():
        pcap = sessions[sess][0]  # 获取会话的第一个数据包
        times = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(pcap.time)
        )  # 格式化时间
        # 提取以太网层信息
        if pcap.haslayer(Ether):
            ether = pcap.getlayer(Ether)
            ether_dst = ether.dst  # 目的MAC
            ether_src = ether.src  # 源MAC
            # 提取IP层信息
            if pcap.haslayer(IP):
                ip = pcap.getlayer(IP)
                ip_src = ip.src  # 源IP
                ip_dst = ip.dst  # 目的IP
            else:
                ip_src = "unknow"
                ip_dst = "unknow"
        else:
            ether_dst = None
            ether_src = None

        # 匹配客户端特征
        clients_str = ""
        for pattern in client_patterns:
            pp = re.compile(pattern, re.S)
            client = pp.findall(str(payload))
            if client:
                clients_str = client[0] + ";" + clients_str
        # 如果有MAC地址和客户端信息,添加到结果列表
        if ether_dst and ether_src and clients_str:
            clientinfo_list.append(
                {
                    "sess": sess,  # 会话ID
                    "ether_dst": ether_dst,  # 目的MAC
                    "ether_src": ether_src,  # 源MAC
                    "ip_src": ip_src,  # 源IP
                    "ip_dst": ip_dst,  # 目的IP
                    "clients": clients_str[:-1],  # 客户端类型
                    "time": times,  # 时间
                }
            )
    return clientinfo_list


# 提取敏感数据
def sen_data(PCAPS, host_ip):
    """
    提取数据包中的敏感数据
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
    Returns:
        sendata_list: 包含敏感数据的列表,包括Web、邮件、Telnet、FTP等协议的数据
    """
    sendata_list = list()  # 存储敏感数据的列表
    # 提取各协议数据
    webdata = web_data(PCAPS, host_ip)  # Web数据
    maildata = mail_data(PCAPS, host_ip)  # 邮件数据
    telnetdata = telnet_ftp_data(PCAPS, host_ip, 23)  # Telnet数据
    ftpdata = telnet_ftp_data(PCAPS, host_ip, 21)  # FTP数据

    # 合并所有协议数据
    sendata_list.extend(webdata)
    sendata_list.extend(maildata)
    sendata_list.extend(telnetdata)
    sendata_list.extend(ftpdata)

    # 提取Telnet协议的账号密码
    telnet_pattern1 = re.compile(r"6c6f67696e3a.*?0d|4c6f67696e3a.*?0d")  # 匹配login:
    telnet_pattern2 = re.compile(
        r"50617373776f72643a.*?0d|70617373776f72643a.*?0d"
    )  # 匹配Password:
    for telnet in telnetdata:
        data = binascii.hexlify(telnet["data"]).decode()  # 转换为十六进制
        login = telnet_pattern1.findall(data)  # 查找登录名
        password = telnet_pattern2.findall(data)  # 查找密码
        restu = ""
        restp = ""
        if login:
            restu = str(
                list(set([binascii.unhexlify(i).strip() for i in login]))
            )  # 解码登录名
        if password:
            restp = str(
                list(set([binascii.unhexlify(i).strip() for i in password]))
            )  # 解码密码
            result = restu + "     " + restp  # 组合结果
            sendata_list.append(result)
