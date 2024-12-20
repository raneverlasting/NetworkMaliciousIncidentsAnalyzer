# -*- coding:utf-8 -*-

"""
视图函数模块,处理所有HTTP请求路由

主要功能:
- 文件上传与处理
- 数据包分析与展示
- 流量分析与可视化
- 数据提取与导出
"""

from app import app
from flask import (
    render_template,
    request,
    flash,
    redirect,
    url_for,
    send_from_directory,
)
from .forms import Upload
from .utils.upload_tools import allowed_file, get_filetype, random_name
from .utils.pcap_decode import PcapDecode
from .utils.pcap_filter import get_all_pcap, proto_filter, showdata_from_id
from .utils.proto_analyzer import (
    common_proto_statistic,
    pcap_len_statistic,
    http_statistic,
    dns_statistic,
    most_proto_statistic,
)
from .utils.flow_analyzer import (
    time_flow,
    data_flow,
    get_host_ip,
    data_in_out_ip,
    proto_flow,
    most_flow_statistic,
)
from .utils.ipmap_tools import getmyip, get_ipmap, get_geo
from .utils.data_extract import (
    web_data,
    telnet_ftp_data,
    mail_data,
    sen_data,
    client_info,
)
from .utils.except_info import exception_warning
from .utils.file_extract import web_file, all_files


from scapy.all import rdpcap
import os
import hashlib

# 导入函数到模板中供jinja2使用
app.jinja_env.globals["enumerate"] = enumerate

# 全局变量
PCAP_NAME = ""  # 当前处理的pcap文件名
PD = PcapDecode()  # pcap解析器实例
PDF_NAME = ""  # 导出PDF文件名
PCAPS = None  # 当前加载的数据包集合


@app.route("/", methods=["POST", "GET"])
@app.route("/index/", methods=["POST", "GET"])
def index():
    """首页视图函数"""
    return render_template("./home/index.html")


@app.route("/upload/", methods=["POST", "GET"])
def upload():
    """
    处理数据包上传
    
    支持pcap/pcapng格式文件上传,并进行格式验证
    上传成功后加载数据包到内存中供后续分析
    """
    filepath = app.config["UPLOAD_FOLDER"]
    upload = Upload()
    if request.method == "GET":
        return render_template("./upload/upload.html")
    elif request.method == "POST":
        pcap = upload.pcap.data
        if upload.validate_on_submit():
            pcapname = pcap.filename
            if allowed_file(pcapname):
                name1 = random_name()
                name2 = get_filetype(pcapname)
                global PCAP_NAME, PCAPS
                PCAP_NAME = name1 + name2
                try:
                    pcap.save(os.path.join(filepath, PCAP_NAME))
                    PCAPS = rdpcap(os.path.join(filepath, PCAP_NAME))
                    flash("恭喜你,上传成功！")
                    return render_template("./upload/upload.html")
                except Exception as e:
                    flash("上传错误,错误信息:" + str(e))
                    return render_template("./upload/upload.html")
            else:
                flash("上传失败,请上传允许的数据包格式!")
                return render_template("./upload/upload.html")
    return render_template("./upload/upload.html")


@app.route("/database/", methods=["POST", "GET"])
def basedata():
    """
    基本数据包信息展示
    
    展示数据包的基本信息,支持按协议类型、源/目的IP等条件过滤
    """
    global PCAPS, PD
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        # 获取筛选的type和value
        filter_type = request.form.get("filter_type", type=str, default=None)
        value = request.form.get("value", type=str, default=None)
        # 如果有选择，通过选择来获取值
        if filter_type and value:
            pcaps = proto_filter(filter_type, value, PCAPS, PD)
        # 默认显示所有的协议数据
        else:
            pcaps = get_all_pcap(PCAPS, PD)
        return render_template("./dataanalyzer/basedata.html", pcaps=pcaps)


@app.route("/datashow/", methods=["POST", "GET"])
def datashow():
    """
    展示单个数据包的详细信息
    
    根据数据包ID显示其详细解析信息,并生成PDF格式报告
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        dataid = request.args.get("id")
        if dataid is not None:
            dataid = int(dataid) - 1
            data = showdata_from_id(PCAPS, dataid)
            PDF_NAME = random_name() + ".pdf"
            PCAPS[dataid].pdfdump(app.config["PDF_FOLDER"] + PDF_NAME)
            return data
        else:
            flash("无效的ID")
            return redirect(url_for("upload"))


@app.route("/savepdf/", methods=["POST", "GET"])
def savepdf():
    """下载数据包详情的PDF报告"""
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        return send_from_directory(
            app.config["PDF_FOLDER"], PDF_NAME, as_attachment=False
        )


@app.route("/protoanalyzer/", methods=["POST", "GET"])
def protoanalyzer():
    """
    协议分析统计
    
    统计分析:
    - 常见协议分布
    - 数据包长度分布
    - HTTP请求统计
    - DNS查询统计
    - 最常见协议TOP统计
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        data_dict = common_proto_statistic(PCAPS)
        pcap_len_dict = pcap_len_statistic(PCAPS)
        pcap_count_dict = most_proto_statistic(PCAPS, PD)

        http_dict = http_statistic(PCAPS)
        # http_dict.items格式 ==> [('123.123.1.2', 3), ('123.123.1.3', 5), ('123.123.1.1', 7)]
        # 下sorted()函数就是将上面的列表按照第二个关键字排序
        http_dict = sorted(http_dict.items(), key=lambda d: d[1], reverse=False)
        http_key_list = list()
        http_value_list = list()
        for key, value in http_dict:
            http_key_list.append(key)
            http_value_list.append(value)

        dns_dict = dns_statistic(PCAPS)
        dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)
        dns_key_list = list()
        dns_value_list = list()
        for key, value in dns_dict:
            dns_key_list.append(key.decode("utf-8"))
            dns_value_list.append(value)
        return render_template(
            "./dataanalyzer/protoanalyzer.html",
            data=list(data_dict.values()),
            pcap_len=pcap_len_dict,
            pcap_keys=list(pcap_count_dict.keys()),
            http_key=http_key_list,
            http_value=http_value_list,
            dns_key=dns_key_list,
            dns_value=dns_value_list,
            pcap_count=pcap_count_dict,
        )


@app.route("/flowanalyzer/", methods=["POST", "GET"])
def flowanalyzer():
    """
    流量分析统计
    
    分析:
    - 时间流量分布
    - 数据流向分析
    - 内外网数据流向
    - 协议流量分布
    - 最大流量会话TOP10
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        time_flow_dict = time_flow(PCAPS)
        host_ip = get_host_ip(PCAPS)
        data_flow_dict = data_flow(PCAPS, host_ip)
        data_ip_dict = data_in_out_ip(PCAPS, host_ip)
        proto_flow_dict = proto_flow(PCAPS)
        most_flow_dict = most_flow_statistic(PCAPS, PD)
        most_flow_dict = sorted(
            most_flow_dict.items(), key=lambda d: d[1], reverse=True
        )
        if len(most_flow_dict) > 10:
            most_flow_dict = most_flow_dict[0:10]
        most_flow_key = list()
        for key, value in most_flow_dict:
            most_flow_key.append(key)
        return render_template(
            "./dataanalyzer/flowanalyzer.html",
            time_flow_keys=list(time_flow_dict.keys()),
            time_flow_values=list(time_flow_dict.values()),
            data_flow=data_flow_dict,
            ip_flow=data_ip_dict,
            proto_flow=list(proto_flow_dict.values()),
            most_flow_key=most_flow_key,
            most_flow_dict=most_flow_dict,
        )


@app.route("/ipmap/", methods=["POST", "GET"])
def ipmap():
    """
    IP地理位置分布
    
    分析IP地理位置分布,生成可视化地图
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        myip = getmyip()
        if myip:
            host_ip = get_host_ip(PCAPS)
            ipdata = get_ipmap(PCAPS, host_ip)

            geo_dict = ipdata[0]
            ip_value_list = ipdata[1]
            myip_geo = get_geo(myip)
            # 将ip_value_list列表里的每一项从字典改为元组
            ip_value_list = [
                (list(d.keys())[0], list(d.values())[0]) for d in ip_value_list
            ]
            print(ip_value_list)
            print(geo_dict)
            print(myip_geo)
            return render_template(
                "./dataanalyzer/ipmap.html",
                geo_data=geo_dict,
                ip_value=ip_value_list,
                mygeo=myip_geo,
            )
        else:
            return render_template("./error/neterror.html")


@app.route("/webdata/", methods=["POST", "GET"])
def webdata():
    """
    Web数据提取
    
    提取HTTP请求和响应数据
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        webdata_list = web_data(PCAPS, host_ip)
        if dataid:
            return webdata_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
        else:
            return render_template("./dataextract/webdata.html", webdata=webdata_list)


@app.route("/maildata/", methods=["POST", "GET"])
def maildata():
    """
    邮件数据提取
    
    提取邮件协议(SMTP/POP3/IMAP)数据,支持附件下载
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        dataid = request.args.get("id")
        filename = request.args.get("filename")
        datatype = request.args.get("datatype")
        host_ip = get_host_ip(PCAPS)
        mailata_list = mail_data(PCAPS, host_ip)
        filepath = app.config["FILE_FOLDER"] + "Mail/"
        if dataid is not None:
            dataid = int(dataid) - 1
            if datatype == "raw":
                raw_data = mailata_list[dataid]["data"]
                with open(filepath + "raw_data.txt", "w", encoding="UTF-8") as f:
                    f.write(raw_data)
            # 其他逻辑
        else:
            flash("无效的ID")
            return redirect(url_for("upload"))
        if filename and dataid:
            filename_ = (
                hashlib.md5(filename.encode("UTF-8")).hexdigest()
                + "."
                + filename.split(".")[-1]
            )
            attachs_dict = mailata_list[int(dataid) - 1]["parse_data"]["attachs_dict"]
            mode = "wb"
            encoding = None
            if isinstance(attachs_dict[filename], str):
                mode = "w"
                encoding = "UTF-8"
            elif isinstance(attachs_dict[filename], bytes):
                mode = "wb"
                encoding = None
            with open(filepath + filename_, mode, encoding=encoding) as f:
                f.write(attachs_dict[filename])
            return send_from_directory(filepath, filename_, as_attachment=True)
        if dataid:
            maildata = mailata_list[int(dataid) - 1]["parse_data"]
            return render_template(
                "./dataextract/mailparsedata.html", maildata=maildata, dataid=dataid
            )
            # return mailata_list[int(dataid) - 1]['data'].replace('\r\n', '<br>')
        else:
            return render_template("./dataextract/maildata.html", maildata=mailata_list)


@app.route("/ftpdata/", methods=["POST", "GET"])
def ftpdata():
    """
    FTP数据提取
    
    提取FTP会话数据和文件传输记录
    """
    if PCAPS is None:
        flash("请先上传要分析得数据包!")
        return redirect(url_for("upload"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        ftpdata_list = telnet_ftp_data(PCAPS, host_ip, 21)
        if dataid:
            return ftpdata_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
        else:
            return render_template("./dataextract/ftpdata.html", ftpdata=ftpdata_list)


@app.route("/telnetdata/", methods=["POST", "GET"])
def telnetdata():
    """
    Telnet数据提取
    
    提取Telnet会话数据和命令记录
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        telnetdata_list = telnet_ftp_data(PCAPS, host_ip, 23)
        if dataid:
            return telnetdata_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
        else:
            return render_template(
                "./dataextract/telnetdata.html", telnetdata=telnetdata_list
            )


@app.route("/clientinfo/", methods=["POST", "GET"])
def clientinfo():
    """
    客户端信息提取
    
    提取HTTP请求中的客户端信息(浏览器、操作系统等)
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        clientinfo_list = client_info(PCAPS)
        return render_template(
            "./dataextract/clientinfo.html", clientinfos=clientinfo_list
        )


@app.route("/sendata/", methods=["POST", "GET"])
def sendata():
    """
    敏感信息提取
    
    提取可能包含敏感信息的数据包(密码、token等)
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        sendata_list = sen_data(PCAPS, host_ip)
        if sendata_list is not None and dataid is not None:
            dataid = int(dataid) - 1
            if 0 <= dataid < len(sendata_list):
                return sendata_list[dataid]["data"].replace("\r\n", "<br>")
            else:
                flash("无效的ID")
                return redirect(url_for("upload"))
        else:
            flash("数据列表未初始化")
            return redirect(url_for("upload"))


@app.route("/exceptinfo/", methods=["POST", "GET"])
def exceptinfo():
    """
    异常数据分析
    
    检测并展示可疑的异常数据包
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        warning_list = exception_warning(PCAPS, host_ip)
        if dataid:
            if warning_list[int(dataid) - 1]["data"]:
                return warning_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
            else:
                return "<center><h3>无相关数据包详情</h3></center>"
        else:
            return render_template("./exceptions/exception.html", warning=warning_list)


@app.route("/webfile/", methods=["POST", "GET"])
def webfile():
    """
    Web文件提取
    
    提取HTTP传输的文件
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        host_ip = get_host_ip(PCAPS)
        filepath = app.config["FILE_FOLDER"] + "Web/"
        web_list = web_file(PCAPS, host_ip, filepath)
        file_dict = dict()
        for web in web_list:
            file_dict[os.path.split(web["filename"])[-1]] = web["filename"]
        file = request.args.get("file")
        if file and file in file_dict:
            filename = (
                hashlib.md5(file.encode("UTF-8")).hexdigest()
                + "."
                + file.split(".")[-1]
            )
            os.rename(filepath + file, filepath + filename)
            return send_from_directory(filepath, filename, as_attachment=True)
        else:
            return render_template("./fileextract/webfile.html", web_list=web_list)


@app.route("/allfile/", methods=["POST", "GET"])
def allfile():
    """
    所有文件提取
    
    提取所有协议中传输的文件
    """
    if PCAPS is None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload"))
    else:
        filepath = app.config["FILE_FOLDER"] + "All/"
        allfiles_dict = all_files(PCAPS, filepath)
        file = request.args.get("file")
        if file and file in allfiles_dict:
            filename = (
                hashlib.md5(file.encode("UTF-8")).hexdigest()
                + "."
                + file.split(".")[-1]
            )
            os.rename(filepath + file, filepath + filename)
            return send_from_directory(filepath, filename, as_attachment=True)
        else:
            return render_template(
                "./fileextract/allfile.html", allfiles_dict=allfiles_dict
            )


@app.errorhandler(404)
def not_found_error(error):
    """404错误处理"""
    return render_template("./error/404.html"), 404


@app.errorhandler(500)
def server_error(error):
    """500错误处理"""
    return render_template("./error/500.html"), 500
