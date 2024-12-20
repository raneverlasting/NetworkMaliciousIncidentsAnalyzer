# -*- coding:utf-8 -*-

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms.validators import DataRequired, AnyOf


class Upload(FlaskForm):
    """用于处理pcap文件上传的表单类"""

    pcap = FileField("pcap", validators=[DataRequired(message="请选择要上传的文件")])


class ProtoFilter(FlaskForm):
    """用于处理协议过滤的表单类"""

    value = FileField("value", description="过滤值")
    filter_type = FileField(
        "filter_type",
        validators=[
            DataRequired(message="过滤类型不能为空"),
            AnyOf(["all", "proto", "ipsrc", "ipdst"], message="无效的过滤类型"),
        ],
        description="过滤类型",
    )
