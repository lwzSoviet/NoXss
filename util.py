#!/usr/bin/python2.7
# -*- encoding: utf-8 -*-
"""
    @Description: Common Utils.
    
    ~~~~~~ 
    @Author  : longwenzhang
    @Time    : 19-10-9 下午12:16
"""
import datetime
import json
import os
import re
import signal
import urllib
import urllib2
import urlparse
from ssl import CertificateError
from urllib2 import URLError
from prettytable import PrettyTable
from selenium import webdriver
from selenium.webdriver import DesiredCapabilities
from config import RESULT_DIR, REQUEST_ERROR, REDIRECT
from cookie import get_cookie, get_cookie_ip, is_ip, get_cookies_list
from httplib import BadStatusLine
from socket import  error as SocketError

proxy_info={'host':'127.0.0.1',
            'port':8080
            }
proxy_support=urllib2.ProxyHandler({'http':'http://%(host)s:%(port)d'%proxy_info})

def change_by_param(url, param, tovalue):
    """
    Change the's param's value to tovalue, only support GET.
    :param url:
    :param param:
    :param tovalue:
    :return:
    """
    url_parsed = urlparse.urlparse(url)
    parsed_dict = dict([(k, v[0]) for k, v in urlparse.parse_qs(url_parsed.query).items()])
    parsed_dict[param] = tovalue
    new_url = url.split("?")[0] + '?' + urllib.urlencode(parsed_dict)
    return new_url

def change_by_value(url, value, tovalue):
    """
    Change the's param's value to tovalue, only support GET.
    :param url:
    :param value:
    :param tovalue:
    :return:
    """
    url_parsed = urlparse.urlparse(url)
    parsed_dict = dict([(k, v[0]) for k, v in urlparse.parse_qs(url_parsed.query).items()])
    for k, v in parsed_dict.items():
        if v == value:
            break
    parsed_dict[k] = tovalue
    new_url = url.split("?")[0] + '?' + urllib.urlencode(parsed_dict)
    return new_url

def get_topdomain(domain):
    if '.' in domain:
        tmp = domain.split('.')
        if len(tmp) == 2:
            return domain
        else:
            topdomain = tmp[-2] + '.' + tmp[-1]
            return topdomain

def get_domain_from_url(url):
    """get domain from url"""
    domain=''
    # url is http://a.b.com/ads/asds
    if re.search(r'://.*?/',url):
        try:
            domain = url.split('//', 1)[1].split('/', 1)[0]
        except IndexError, e:
            print 'Get domain error,%s,%s' % (url, e)
    # http://a.b.com?a=adsd
    elif re.search(r'://.*?\?',url):
        try:
            domain = url.split('//', 1)[1].split('?', 1)[0]
        except IndexError, e:
            print 'Get domain error,%s,%s' % (url, e)
    elif re.search(r'://.*?',url):
        try:
            domain = url.split('//', 1)[1].split('/', 1)[0]
        except IndexError, e:
            print 'Get domain error,%s,%s' % (url, e)
    # url is a.b.com/a/b/c, a.b.com, /a/b/c,
    elif re.search(r'/',url):
        value = url.split('/', 1)[0]
        if value=='':
            pass
        elif value=='.':
            pass
        elif '.' not in value:
            pass
        elif domain=='..':
            pass
    return domain

def list2dict(list):
    dict={}
    for i in list:
        try:
            key, value = i.split(': ')[0], i.split(': ')[1]
            value = value.replace('\r\n', '')
            dict[key] = value
        except IndexError:
            pass
    return dict

# cookie str to dict
def cookiestr2dict(cookie_str):
    cookie_dict={}
    new_list = [i.strip() for i in cookie_str.split(';')]
    for i in new_list:
        if i != '':
            key = i.split('=')[0]
            value = i.split('=')[1]
            cookie_dict[key] = value
    return cookie_dict

# cookie dict to cookie-str
def cookiedict2str(cookie_dict):
    cookiestr=''
    for key,value in cookie_dict.items():
        cookiestr+=key+'='+value+';'+' '
    return cookiestr

class RedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):
        print 'ignore 301'
    def http_error_302(self, req, fp, code, msg, headers):
        print 'ignore 302'

def getheader(target_domain):
    # add UA
    header = [
        ('User-Agent','Mozilla/2.0 (X11; Linux x86_64) AppleWebKit/237.36 (KHTML, like Gecko) Chrome/62.0.3322.146 Safari/237.36'),

    ]
    #  add cookie
    if is_ip(target_domain):
        ip=target_domain
        cookie=get_cookie_ip(ip)
    else:
        cookie = get_cookie(target_domain)
    # if cookie is in date,add it
    if cookie:
        header.append(('Cookie', cookie))
    #  referer bypass
    header.append(('Referer','https://'+target_domain+'/'))
    return header


def getheader_dict(target_domain):
    # add UA
    header = {
        'User-Agent':'Mozilla/2.0 (X11; Linux x86_64) AppleWebKit/237.36 (KHTML, like Gecko) Chrome/62.0.3322.146 Safari/237.36',
    }
    #  add cookie
    cookie = get_cookie(target_domain)
    # if cookie is in date,add it
    if cookie:
        header['Cookie']= cookie
    #  add referer
    header['Referer']='https://'+target_domain+'/'
    return header

def getheader_without_cookie(target_domain):
    # add UA
    header = [
        ('User-Agent',
         'Mozilla/2.0 (X11; Linux x86_64) AppleWebKit/237.36 (KHTML, like Gecko) Chrome/62.0.3322.146 Safari/237.36'),

    ]
    #  add referer
    header.append(('Referer', 'https://' + target_domain + '/'))
    return header

# get and post request, with headers
def make_request(method,url,headers,body):
    domain = get_domain_from_url(url)
    if headers:
        # delete some needless header
        for key in headers.keys():
            if key in ['Accept-Encoding','Content-Type','Accept-Language','Accept','Connection']:
                del headers[key]
    else:
        headers = getheader_dict(domain)
    # proxy(127.0.0.1:8080)
    # opener=urllib2.build_opener(proxy_support)
    # opener = urllib2.build_opener()
    # opener.addheaders=headers
    # urllib2.install_opener(opener)
    if method =='GET':
        req = urllib2.Request(url, headers=headers)
        try:
            resp = urllib2.urlopen(req)
            # save redirect
            if resp.url!=url:
                REDIRECT.append(url)
            return resp
        except URLError, e:
            REQUEST_ERROR.append(('make_request()',url,e.reason))
        except CertificateError:
            REQUEST_ERROR.append(('make_request()', url, 'ssl.CertificateError'))
        except ValueError, e:
            print e
        except BadStatusLine,e:
            print e
        except SocketError,e:
            print e
    elif method=='POST':
        req = urllib2.Request(url, data=body, headers=headers)
        try:
            resp = urllib2.urlopen(req)
            if resp.url!=url:
                REDIRECT.append(url)
            return resp
        except URLError, e:
            REQUEST_ERROR.append(('make_request()',url,e.reason))
        except CertificateError:
            REQUEST_ERROR.append(('make_request()', url, 'ssl.CertificateError'))
        except ValueError, e:
            print e
        except BadStatusLine,e:
            print e
        except SocketError,e:
            print e

def chrome():
    # support to get response status and headers
    d = DesiredCapabilities.CHROME
    d['loggingPrefs'] = {'performance': 'ALL'}
    opt = webdriver.ChromeOptions()
    # opt.set_headless()
    opt.add_argument("--disable-xss-auditor")
    opt.add_argument("--disable-web-security")
    opt.add_argument("--allow-running-insecure-content")
    opt.add_argument("--no-sandbox")
    opt.add_argument("--disable-setuid-sandbox")
    opt.add_argument("--disable-webgl")
    opt.add_argument("--disable-popup-blocking")
    # prefs = {"profile.managed_default_content_settings.images": 2,
    #          'notifications': 2,
    #          }
    # opt.add_experimental_option("prefs", prefs)
    browser = webdriver.Chrome(options=opt,desired_capabilities=d)
    browser.implicitly_wait(10)
    browser.set_page_load_timeout(20)
    return browser

def phantomjs():
    """use phantomjs"""
    browser = webdriver.PhantomJS(service_args=['--load-images=no', '--disk-cache=yes','--ignore-ssl-errors=true'])
    browser.implicitly_wait(10)
    browser.set_page_load_timeout(20)
    return browser

def add_cookie(browser,url):
    try:
        browser.get(url)
    except Exception, e:
        print 'First visit Error:%s' % e
    else:
        domain = get_domain_from_url(url)
        cookies_list = get_cookies_list(domain)
        for i in cookies_list:
            browser.add_cookie(i)

def getResponseHeaders(type,browser):
    if type=='phantomjs':
        try:
            har = json.loads(browser.get_log('har')[0]['message'])
            return dict(
                [(header["name"], header["value"]) for header in har['log']['entries'][0]['response']["headers"]],
                key=lambda x: x[0])
        except:
            return {}
    elif type=='chrome':
        for responseReceived in browser.get_log('performance'):
            try:
                response = json.loads(responseReceived['message'])['message']['params']['response']
                if response['url'] == browser.current_url:
                    temp=response['headers']
                    return temp
            except:
                pass
        return {}

def getResponseStatus(type,browser):
    if type=='phantomjs':
        har = json.loads(browser.get_log('har')[0]['message'])
        return (har['log']['entries'][0]['response']["status"], str(har['log']['entries'][0]['response']["statusText"]))
    elif type=='chrome':
        for responseReceived in browser.get_log('performance'):
            try:
                response = json.loads(responseReceived[u'message'])[u'message'][u'params'][u'response']
                if response[u'url'] == browser.current_url:
                    return (response[u'status'], response[u'statusText'])
            except:
                pass
        return None

def check_type(value):
    """
    Check the value means number or string.
    :param value: str
    :return: type
    """
    try:
        int(value)
    except ValueError:
        try:
            float(value)
        except ValueError:
            type='string'
            return type

def str2dict(str):
    try:
        return eval(str)
    except SyntaxError:
        return {}

def dict2str(dict):
    return str(dict)

def gen_poc(*args):
    """
    Generate poc.
    :param args:
    :return:
    """
    return '$$$$$$'.join(args)

def divide_list(a,b):
    """

    :param a: list
    :param b: length
    :return:
    """
    result=[]
    group_number=len(a)/b
    start=0
    for i in range(group_number):
        end=(i+1)*b
        result.append(a[start:end])
        start=end
    if len(a)>end:
        result.append(a[end:])
    return result

def gen_id():
    return ''.join(map(lambda xx: (hex(ord(xx))[2:]), os.urandom(8)))

def print_result_table(result):
    '''
    :param domain:
    :param task_id:
    :return:
    '''
    table = PrettyTable(['ID', 'VUL', 'URL','POC'])
    table.align = 'l'
    table.sortby ='ID'
    id=1
    if result:
        for vul,url,poc in result:
            table.add_row([id,vul,url,poc])
            id+=1
        try:
            print table
        except UnicodeDecodeError,e:
            print e

def save(result,id):
    result_dict={}
    if result:
        for vul,location,poc in result:
            print_warn('%s found in: %s\n'%(vul,location))
            if vul in result_dict.keys():
                result_dict[vul].append((location,poc))
            else:
                result_dict[vul]=[]
                result_dict[vul].append((location,poc))
        print_result_table(result)
        result_file = os.path.join(RESULT_DIR, id +'-'+ datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S") + '.json')
        with open(result_file,'w') as json_f:
            json.dump(result_dict, json_f)
            print_info('The result of %s has been saved to %s'%(id,result_file))

class Func_timeout_error(Exception):
    def __str__(self):
        return '<func timeout!!!>'

def functimeout(maxtime):
    def wrap(func):
        def inner(*args):
            def handle(signum,frame):
                raise Func_timeout_error
            signal.signal(signal.SIGALRM, handle)
            signal.alarm(maxtime)
            result=func(*args)
            return result
        return inner
    return wrap

def print_warn(msg):
    print '\033[1;31m{}\033[0m'.format(msg)

def print_info(msg):
    print '\033[1;32m{}\033[0m'.format(msg)

if __name__=="__main__":
    pass