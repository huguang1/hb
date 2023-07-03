#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Author: June
# @Time : 2019/3/21
# import binascii
# str1 = '7B-22-70-69-6E-67-22-3A-31-35-35-33-31-34-30-35-33-36-31-38-34-2C-22-72-74-74-22-3A-35-36-39-7D'
# a = str1.split('-')
# str2 = ''
# for i in a:
#     str2 += i
# b = binascii.unhexlify(str2).decode('utf-8')
# print(b)
import time
from datetime import datetime, timedelta
now = datetime.today()
monday = now-timedelta(days=now.weekday())
month = datetime(now.year, now.month, 1).timestamp()
year = datetime(now.year, 1, 1).timestamp()
day = datetime(now.year, now.month, now.day).timestamp()
week = datetime(monday.year, monday.month, monday.day).timestamp()
print(month, year, week, day)
print(datetime.today().timestamp())
# print(time.time())