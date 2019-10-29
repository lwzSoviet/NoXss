#!/usr/bin/env python  
# -*- coding: utf-8 -*-
"""Do some work about cookie"""
import os
import re
import time
from config import COOKIE_DIR

__author__ = 'longwenzhang'

def is_ip(domain):
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}',domain):
        return True

# get cookie for browser
def get_cookies_list(target_domain):
    cookies_list = []
    # if ip
    if is_ip(target_domain):
        domain_scope=target_domain
    else:
        domain_scope = '.' + target_domain.split('.')[-2] + '.' + target_domain.split('.')[-1]
    cookie_file_path=os.path.join(COOKIE_DIR,'_'.join([domain_scope,'cookie']))
    if os.path.exists(cookie_file_path):
        with open(cookie_file_path, "r")as cookie_file:
            cookie_file_list = cookie_file.readlines()
            expire = cookie_file_list[2]
            # check expire
            if int(time.time())<int(expire):
                cookies_text = cookie_file_list[0].strip()
                domain = cookie_file_list[1].strip()
                new_list = cookies_text.split(';')
                for i in new_list:
                    if i != '':
                        cookie_dict = {}
                        key = i.split('=')[0].strip()
                        value = i.split('=')[1].strip()
                        cookie_dict['domain'] = domain
                        cookie_dict['name'] = key
                        cookie_dict['value'] = value
                        cookie_dict['path'] = '/'
                        cookies_list.append(cookie_dict)
    return cookies_list

# save cookie default expire=360000s
def save_cookie(cookie,domain,expire_time=360000):
    domain_scope='.'+domain.split('.')[-2]+'.'+domain.split('.')[-1]
    expire=int(time.time())+expire_time
    with open(os.path.join(COOKIE_DIR,'_'.join([domain_scope,'cookie'])), 'w+')as cookie_file:
        cookie_file.write(cookie + '\n')
        cookie_file.write(domain_scope+'\n')
        cookie_file.write(str(expire))

#  save cookie for http://ip/path
def save_cookie_ip(cookie,ip,expire_time=360000):
    domain_scope=ip
    print domain_scope
    expire=int(time.time())+expire_time
    with open(os.path.join(COOKIE_DIR,'_'.join([domain_scope,'cookie'])), 'w+')as cookie_file:
        cookie_file.write(cookie + '\n')
        cookie_file.write(domain_scope+'\n')
        cookie_file.write(str(expire))

# get cookie
def get_cookie(target_domain,):
    try:
        domain_scope = '.' + target_domain.split('.')[-2] + '.' + target_domain.split('.')[-1]
        cookie_file_path = os.path.join(COOKIE_DIR, '_'.join([domain_scope, 'cookie']))
        if os.path.exists(cookie_file_path):
            with open(cookie_file_path, "r")as cookie_file:
                cookie_file_list = cookie_file.readlines()
                expire = cookie_file_list[2]
                # check expire
                if int(time.time()) < int(expire):
                    cookies_text = cookie_file_list[0].strip()
                    return cookies_text
                else:
                    print 'Cookie of %s is expired!!!' % domain_scope
        # cookie 不存在
        else:
            pass
            # print 'Cookie of %s not exist!!!' % domain_scope
    except IndexError,e:
        print e

# get cookie-ip
def get_cookie_ip(ip,):
    try:
        domain_scope = ip
        cookie_file_path = os.path.join(COOKIE_DIR, '_'.join([domain_scope, 'cookie']))
        if os.path.exists(cookie_file_path):
            with open(cookie_file_path, "r")as cookie_file:
                cookie_file_list = cookie_file.readlines()
                expire = cookie_file_list[2]
                # check expire
                if int(time.time()) < int(expire):
                    cookies_text = cookie_file_list[0].strip()
                    return cookies_text
                else:
                    print 'Cookie of %s is expired!!!' % domain_scope
        else:
            pass
            # print 'Cookie of %s not exist!!!' % domain_scope
    except IndexError,e:
        print e

# get all cookies about one domain,for logic-scan
def get_all_cookie(domain):
    pass

if __name__=='__main__':
    pass