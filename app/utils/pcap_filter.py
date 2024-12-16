# -*- coding:utf-8 -*-

import collections
import tempfile
import sys


def get_all_pcap(PCAPS, PD):
    '''
    对于pcap文件进行文件处理，返回字典格式
    '''
    pcaps = collections.OrderedDict()
    for count, i in enumerate(PCAPS, 1):
        pcaps[count] = PD.ether_decode(i)
    return pcaps


def get_filter_pcap(PCAPS, PD, key, value):
    '''
    将具体的协议进行筛选返回
    '''
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
    # 将pcap筛选后记录按序返回
    return pcaps


def proto_filter(filter_type, value, PCAPS, PD):
    '''
    协议过滤，根据选择挑选出正确的协议显示
    可以根据"起始地址：端口","目的地址：端口","协议"筛选
    '''
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
    pcap = PCAPS[dataid]
    # 输出重定向数据, 将pcap.show()命令的输出内容保存到文件show_temp_name中
    show_temp_name = tempfile.NamedTemporaryFile(prefix='show_', dir='/tmp')
    old = sys.stdout
    show_file = open(show_temp_name.name, 'w')
    sys.stdout = show_file
    pcap.show()
    sys.stdout = old
    show_file.close()
    # 读取数据
    with open(show_temp_name.name, 'r') as showf:
        data = showf.read()
    result = data.strip().split('###')[1:]
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
    all_html = ''
    id = 0
    for proto, value in zip(result[::2], result[1::2]):
        # zip(xxx)的格式：
        # [('[ TCP ]',' \n  dst       = 9c:2a:70:3f:03:cc\n  src       = d4:ee:07:2b:dd:12\n  type      = IPv4\n'),
        #  ('[ IP ]',' \n     version   = 4\n     ihl       = 5\n     tos       = 0x0\n     len       = 64\n     id        = 64613\n     flags     = DF\n     frag      = 0\n     ttl       = 56\n     proto     = tcp\n     chksum    = 0x8a82\n     src       = 115.231.191.156\n     dst       = 192.168.199.163\n     \\options   \\\n')]
        id += 1
        html_proto = proto.strip()[1:-1].strip()  # [ TCP ] ===> TCP
        html_values = ''
        values = value.strip().split('\n')  # ['dst       = 9c:2a:70:3f:03:cc', '  src       = d4:ee:07:2b:dd:12', '  type      = IPv4']
        for v in values:
            val = v.split('  =')  # ['dst      ', ' 9c:2a:70:3f:03:cc']
            if len(val) == 2:
                html_values += '<b>{0} = {1}</b><br>'.format(val[0].strip(), val[1].strip())
            elif len(val) == 1:
                html_values += '<b>{0} = {1}</b><br>'.format('options', 'None')
        all_html += html.format(proto=html_proto,
                                values=html_values, id=str(id))
    return all_html
