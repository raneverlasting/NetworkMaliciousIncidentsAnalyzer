# -*- coding:utf-8 -*-

import random


def allowed_file(filename):
    """
    验证上传文件的后缀名是否合法
    
    Args:
        filename: 文件名
        
    Returns:
        bool: 如果后缀名在允许列表中返回True,否则返回False
    """
    ALLOWED_EXTENSIONS = set(["pcap", "cap"])
    return "." in filename and filename.rsplit(".", 1)[1] in ALLOWED_EXTENSIONS


def get_filetype(filename):
    """
    获取文件的后缀名
    
    Args:
        filename: 文件名
        
    Returns:
        str: 以点号开头的文件后缀名
    """
    return "." + filename.rsplit(".", 1)[1]


def random_name():
    """
    生成10位随机字符串作为文件名
    
    Returns:
        str: 由数字和小写字母组成的10位随机字符串
    """
    return "".join(random.sample("1234567890qazxswedcvfrtgbnhyujmkiolp", 10))
