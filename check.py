#!/usr/bin/python2.7
# -*- encoding: utf-8 -*-
"""
    @Description: Check if the browser installed correctly.
    
    ~~~~~~ 
    @Author  : longwenzhang
    @Time    : 19-10-29   3:46
"""
import urllib2

from selenium import webdriver
from util import print_info, print_warn

def check_install():
    try:
        br=webdriver.Chrome()
    except Exception, e:
        print e
        try:
            br=webdriver.PhantomJS()
        except Exception, e:
            print e
            print_warn('No browser is installed correctly!')
        else:
            br.quit()
            print_info('Phantomjs is installed correctly.')
    else:
        br.quit()
        print_info('Chrome is installed correctly.')
        try:
            br=webdriver.PhantomJS()
        except Exception, e:
            print e
        else:
            br.quit()
            print_info('Phantomjs is installed correctly.')
    exit(0)

def check_url(url):
    try:
        urllib2.urlopen(url,timeout=20)
    except Exception,e:
        print 'Check url error: '+str(e)
        exit(0)
