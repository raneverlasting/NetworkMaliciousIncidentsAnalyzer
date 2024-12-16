# -*- coding:utf-8 -*-

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms.validators import DataRequired, AnyOf


# 上传文件的表单
class Upload(FlaskForm):
    pcap = FileField("pcap", validators=[DataRequired()])


# 协议过滤的表单
class ProtoFilter(FlaskForm):
    value = FileField("value")
    filter_type = FileField(
        "filter_type",
        validators=[DataRequired(), AnyOf(["all", "proto", "ipsrc", "ipdst"])],
    )
