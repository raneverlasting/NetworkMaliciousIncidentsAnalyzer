# -*- coding:utf-8 -*-

from flask import Flask

import sys
import os

# 将项目根目录添加到Python模块搜索路径,以便导入项目模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# 导入配置文件
import config  # noqa

# 创建Flask应用实例
app = Flask(__name__)

# 从config.py加载配置
app.config.from_object("config")

# 导入视图函数
# 注意:必须在创建app实例之后导入views,避免循环导入
from app import views  # noqa
