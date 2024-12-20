# -*- coding:utf-8 -*-

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DEBUG = True

WTF_CSRF_ENABLED = False

SECRET_KEY = "!@#$%8F6F98EC3684AECA1DC44E1CB816E4A5^&*()"

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads', 'PCAP')
FILE_FOLDER = os.path.join(BASE_DIR, 'uploads', 'Files')
PDF_FOLDER = os.path.join(BASE_DIR, 'uploads', 'Files', 'PDF')
