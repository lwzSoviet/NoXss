#!/usr/bin/python2.7
# -*- encoding: utf-8 -*-
"""
    @Description: Check if the browser installed correctly.
    
    ~~~~~~ 
    @Author  : longwenzhang
    @Time    : 19-10-29   3:46
"""
import urllib2
from log import LOGGER
from selenium import webdriver

def check_install():
    try:
        br=webdriver.Chrome()
    except Exception, e:
        LOGGER.info(e)
        try:
            br=webdriver.PhantomJS()
        except Exception, e:
            LOGGER.info(e)
            LOGGER.warn('No browser is installed correctly!')
        else:
            br.quit()
            LOGGER.info('Phantomjs is installed correctly.')
    else:
        br.quit()
        LOGGER.info('Chrome is installed correctly.')
        try:
            br=webdriver.PhantomJS()
        except Exception, e:
            LOGGER.info(e)
        else:
            br.quit()
            LOGGER.info('Phantomjs is installed correctly.')
    exit(0)

def check_url(url):
    try:
        urllib2.urlopen(url,timeout=20)
    except Exception,e:
        LOGGER.warn('Check url error: '+str(e))
        exit(0)
