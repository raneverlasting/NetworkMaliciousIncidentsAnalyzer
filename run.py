# -*- coding:utf-8 -*-
# 第一个 app 指的是目录 app 下的 __init__.py 文件
# 第二个 app 是 __init__.py 中定义的 Flask 实例
# 导入 __init__.py 中定义的对象时使用：from init_dir import xxx
from app import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
