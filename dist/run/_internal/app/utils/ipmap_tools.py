# -*- coding:utf-8 -*-

from scapy.all import corrupt_bytes
from scapy.layers.inet import IP
import requests
import os
import geoip2.database


def getmyip():
    """
    获取本机外网IP
    Returns:
        str: 本机外网IP地址,获取失败返回None
    """
    try:
        # 使用百度爬虫UA避免被屏蔽
        headers = {"User-Agent": "Baiduspider+(+http://www.baidu.com/search/spider.htm"}
        # 通过icanhazip.com获取外网IP
        ip = requests.get("http://icanhazip.com", headers=headers).text
        return ip.strip()
    except requests.RequestException:
        return None


def get_geo(ip):
    """
    获取IP地址的地理位置信息
    Args:
        ip: IP地址
    Returns:
        list: [城市名称,经度,纬度],获取失败返回None
    """
    # 获取GeoIP数据库路径
    current_dir = os.path.abspath(os.path.dirname(__file__))
    geoip_database_path = os.path.join(current_dir, "GeoIP", "GeoLite2-City.mmdb")
    # 初始化GeoIP数据库读取器
    reader = geoip2.database.Reader(geoip_database_path)
    try:
        # 查询IP地址信息
        response = reader.city(ip)
        # 优先获取中文名称,否则使用英文名称,都没有则使用默认值
        country_name = response.country.names.get(
            "zh-CN", response.country.names.get("en", "未知国家")
        )
        city_name = response.city.names.get(
            "zh-CN", response.city.names.get("en", "未知城市")
        )
        # 组合完整地名
        city_name = country_name + city_name
        # 获取经纬度
        longitude = response.location.longitude
        latitude = response.location.latitude
        return [city_name, longitude, latitude]
    except Exception as e:
        print(f"获取地理位置信息错误: {str(e)}")
        return None


def get_ipmap(PCAPS, host_ip):
    """
    获取IP地图数据
    Args:
        PCAPS: 数据包列表
        host_ip: 主机IP
    Returns:
        list: [地理位置字典,IP流量列表]
    """
    # 存储地理位置信息的字典
    geo_dict = dict()
    # 存储IP流量统计的字典
    ip_value_dict = dict()
    # 存储最终IP流量数据的列表
    ip_value_list = list()
    
    # 遍历所有数据包
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            # 获取数据包大小
            pcap_len = len(corrupt_bytes(pcap))
            # 确定对端IP
            if src == host_ip:
                oip = dst
            else:
                oip = src
            # 累计IP流量
            if oip in ip_value_dict:
                ip_value_dict[oip] += pcap_len
            else:
                ip_value_dict[oip] = pcap_len
                
    # 处理每个IP的地理位置和流量信息
    for ip, value in ip_value_dict.items():
        geo_list = get_geo(ip)
        if geo_list:
            # 保存地理位置信息
            geo_dict[geo_list[0]] = [geo_list[1], geo_list[2]]
            # 转换流量单位为KB并格式化
            Mvalue = str(float("%.2f" % (value / 1024.0))) + ":" + ip
            ip_value_list.append({geo_list[0]: Mvalue})
        else:
            pass
    return [geo_dict, ip_value_list]
