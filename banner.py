#!/usr/bin/python2.7
# -*- encoding: utf-8 -*-
"""
    @Description: print logo.
    
    ~~~~~~ 
    @Author  : longwenzhang
    @Time    : 19-10-9  10:28
"""
import os
from config import BASE_DIR

def banner():
    with open(os.path.join(BASE_DIR,'logo'))as banner_f:
        a=banner_f.read()
    BANNER = """\033[01;33m"""+a+"""\033[0m"""
    print BANNER

if __name__=='__main__':
    banner()