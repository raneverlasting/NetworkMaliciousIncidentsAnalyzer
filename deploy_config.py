# -*- coding:utf-8 -*-

bind = "0.0.0.0:8000"  # 绑定的IP地址和端口
workers = 1  # worker进程的数量
backlog = 2048  # 等待连接的最大数量
debug = True  # 是否开启调试模式
proc_name = "gunicorn.pid"  # 进程名
pidfile = "/var/log/gunicorn/debug.log"  # PID文件路径
loglevel = "debug"  # 日志级别
