# -*- coding:utf-8 -*-

import collections
import tempfile
import sys


def get_all_pcap(PCAPS, PD):
    """
    获取所有数据包的解析结果
    
    Args:
        PCAPS: 数据包列表
        PD: 协议解析器对象
        
    Returns:
        OrderedDict: 包含所有数据包解析结果的有序字典,key为序号,value为解析结果
    """
    pcaps = collections.OrderedDict()
    for count, i in enumerate(PCAPS, 1):
        pcaps[count] = PD.ether_decode(i)
    return pcaps


def get_filter_pcap(PCAPS, PD, key, value):
    """
    根据过滤条件筛选数据包
    
    Args:
        PCAPS: 数据包列表
        PD: 协议解析器对象
        key: 过滤字段名(Protocol/Source/Destination)
        value: 过滤字段值
        
    Returns:
        OrderedDict: 包含过滤后数据包的有序字典,key为序号,value为解析结果
    """
    pcaps = collections.OrderedDict()
    count = 1
    for p in PCAPS:
        pcap = PD.ether_decode(p)
        if key == 'Procotol':
            if value == pcap.get('Procotol').upper():
                pcaps[count] = pcap
                count += 1
            else:
                pass
        elif key == 'Source':
            if value == pcap.get('Source').upper():
                pcaps[count] = pcap
                count += 1
        elif key == 'Destination':
            if value == pcap.get('Destination').upper():
                pcaps[count] = pcap
                count += 1
        else:
            pass
    return pcaps


def proto_filter(filter_type, value, PCAPS, PD):
    """
    根据过滤类型和值过滤数据包
    
    Args:
        filter_type: 过滤类型(all/proto/ipsrc/ipdst)
        value: 过滤值
        PCAPS: 数据包列表
        PD: 协议解析器对象
        
    Returns:
        OrderedDict: 包含过滤后数据包的有序字典
    """
    if filter_type == u'all':
        pcaps = get_all_pcap(PCAPS, PD)
    elif filter_type == u'proto':
        key = 'Procotol'
        value = str(value).strip().upper()
        pcaps = get_filter_pcap(PCAPS, PD, key, value)
    elif filter_type == u'ipsrc':
        key = 'Source'
        value = str(value).strip().upper()
        pcaps = get_filter_pcap(PCAPS, PD, key, value)
    elif filter_type == u'ipdst':
        key = 'Destination'
        value = str(value).strip().upper()
        pcaps = get_filter_pcap(PCAPS, PD, key, value)
    else:
        pcaps = get_all_pcap(PCAPS, PD)
    return pcaps


def showdata_from_id(PCAPS, dataid):
    """
    根据数据包ID生成详细信息的HTML展示
    
    Args:
        PCAPS: 数据包列表
        dataid: 数据包ID
        
    Returns:
        str: 包含数据包详细信息的HTML字符串
    """
    pcap = PCAPS[dataid]
    # 重定向stdout到临时文件以捕获pcap.show()输出
    show_temp_name = tempfile.NamedTemporaryFile(prefix='show_', dir='/tmp')
    old = sys.stdout
    show_file = open(show_temp_name.name, 'w')
    sys.stdout = show_file
    pcap.show()
    sys.stdout = old
    show_file.close()

    # 读取并解析show()输出
    with open(show_temp_name.name, 'r') as showf:
        data = showf.read()
    result = data.strip().split('###')[1:]

    # HTML模板
    html = '''
            <div class="accordion-group">
                <div class="accordion-heading">
                    <b><a class="accordion-toggle" data-toggle="collapse" data-parent="#accordion" href="#collapse{id}">
                        {proto}
                    </a></b><br>
                </div>
                <div id="collapse{id}" class="accordion-body collapse" style="height: 0px; ">
                    <div class="accordion-inner">
                        {values}
                    </div>
                </div>
            </div>
    '''

    # 生成HTML内容
    all_html = ''
    id = 0
    for proto, value in zip(result[::2], result[1::2]):
        id += 1
        html_proto = proto.strip()[1:-1].strip()
        html_values = ''
        values = value.strip().split('\n')
        for v in values:
            val = v.split('  =')
            if len(val) == 2:
                html_values += '<b>{0} = {1}</b><br>'.format(val[0].strip(), val[1].strip())
            elif len(val) == 1:
                html_values += '<b>{0} = {1}</b><br>'.format('options', 'None')
        all_html += html.format(proto=html_proto,
                                values=html_values, id=str(id))
    return all_html
