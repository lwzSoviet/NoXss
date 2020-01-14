#!/usr/bin/python2.7
# -*- encoding: utf-8 -*-
"""
    @Description: Core of NoXss,include preprocess,detect,scan,e.g.

    ~~~~~~
    @Author  : longwenzhang
    @Time    : 19-10-9  10:13
"""
import cPickle
import os
import time
import urllib
import urllib2
from Queue import Empty
from httplib import BadStatusLine
from multiprocessing import Process, Manager
import json
import re
import urlparse
from ssl import CertificateError
from xml.etree import cElementTree
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from config import TRAFFIC_DIR, REQUEST_ERROR, REDIRECT, MULTIPART
from cookie import get_cookie
from model import Case, HttpRequest, HttpResponse
from util import functimeout, Func_timeout_error, change_by_param, list2dict, print_info, chrome, phantomjs, \
    getResponseHeaders, check_type, add_cookie, \
    get_domain_from_url, print_warn, divide_list, make_request, gen_poc, get_api
import gevent
from gevent import pool
from socket import error as SocketError
try:
    from bs4 import BeautifulSoup
except ImportError, e:
    print e
# def _pickle_method(m):
#     if m.im_self is None:
#         return getattr, (m.im_class, m.im_func.func_name)
#     else:
#         return getattr, (m.im_self, m.im_func.func_name)

static_reg = re.compile(r'\.html$|\.htm$|\.shtml$|\.css$|\.png$|\.js$|\.dpg$|\.jpg$|\.svg$|\.jpeg$|'
                            r'\.gif$|\.webp$|\.ico$|\.woff$|\.ttf$|css\?|js\?|jpg\?|png\?|woff\?v='
                            r'|woff2\?v=|ttf\?|woff\?|woff2$|html\?v=|ico$')
burp_traffic = []
manager = Manager()
case_list = manager.list()
openner_result = manager.list()
# for deduplicate
# api_list=manager.list()
# filtered=manager.list()
traffic_queue = manager.Queue()
# for saving ot local file
traffic_list = manager.list()
# save reflect for analyzing
reflect_list = manager.list()
# filter
api_list = manager.list()

class Traffic_generator(Process):
    DEFAULT_HEADER = {
        'User-Agent': 'Mozilla/2.0 (X11; Linux x86_64) AppleWebKit/237.36 (KHTML, like Gecko) Chrome/62.0.3322.146 Safari/237.36',
    }

    def __init__(self, id, url_list,coroutine):
        Process.__init__(self)
        self.id = id
        self.url_list = url_list
        self.coroutine=coroutine

    def gen_traffic(self, url):
        domain = get_domain_from_url(url)
        # add cookie to DEFAULT_HEADER
        cookie = get_cookie(domain)
        self.DEFAULT_HEADER['Cookie'] = cookie
        # add referer
        self.DEFAULT_HEADER['Referer'] = 'https"//' + domain + '/'
        request = HttpRequest(method='GET', url=url, headers=self.DEFAULT_HEADER, body='')
        req = urllib2.Request(url=url, headers=self.DEFAULT_HEADER)
        with gevent.Timeout(10, False)as t:
            try:
                resp = urllib2.urlopen(req)
            except urllib2.URLError, e:
                REQUEST_ERROR.append(('gen_traffic()', url, e.reason))
            except CertificateError:
                REQUEST_ERROR.append(('gen_traffic()', url, 'ssl.CertificateError'))
            except ValueError, e:
                print e
            except BadStatusLine, e:
                print e
            except SocketError, e:
                print e
            else:
                if resp.url != url:
                    REDIRECT.append(url)
                try:
                    data = resp.read()
                except Exception, e:
                    print e
                else:
                    resp_headers = resp.headers.headers
                    resp_headers_dict = list2dict(resp_headers)
                    response = HttpResponse(code=str(resp.code), reason=resp.msg, headers=resp_headers_dict,
                                            data=data)
                    return (request, response)

    def run(self):
        import gevent
        from gevent import monkey
        monkey.patch_all()
        from gevent import pool
        # default 200
        # g_pool = pool.Pool(200)
        g_pool = pool.Pool(self.coroutine)
        tasks = [g_pool.spawn(self.gen_traffic, url) for url in self.url_list]
        gevent.joinall(tasks)
        traffic_list = []
        for i in tasks:
            if i.value is not None:
                traffic_list.append(i.value)
        # save traffic for rescan
        Engine.save_traffic(traffic_list, self.id)

class Detector():
    """
    Do some detect-work,e.g.,detect the param and value in url(https://example.com/test?a=1&b=2--->{a:1,b:2}),
    detect the reflect param's position in the response(in html,js or tag's value).
    """

    @staticmethod
    def detect_json(json_str):
        """

        :param json_str: json-type string,e.g.,"{a:'x','b':'y'}"
        :return: dict-type e.g.,{'a':'x','b':'y'}
        """
        result_dict = {}
        json_str.replace('\'', '\"')
        try:
            json_dict = json.loads(json_str)
        except ValueError:
            print 'Error in detect_json():%s' % json_str
        else:
            # other type to str
            for k, v in json_dict.items():
                if isinstance(v, str):
                    result_dict.update(k=v)
                elif isinstance(v, int):
                    result_dict.update(k=str(v))
                else:
                    pass
            return result_dict

    @staticmethod
    def parse_by_token(data):
        result = {}
        split_symbol = ','
        data = re.sub(r'[\\\'\"{}\[\]]', '', data)
        if ',' in data:
            groups = data.split(split_symbol)
            for i in groups:
                if ':' in i:
                    k, v = i.split(':')[0], i.split(':')[1]
                    result[k] = v
            return result
        else:
            print 'Can\'t parse body:\n%s' % data

    @staticmethod
    def detect_param(request):
        """
        :param request: httprequest
        :return: param_dict
        """
        param_dict = {}
        method, url, body = request.method, request.url, request.body
        if method == 'GET':
            url_parsed = urlparse.urlparse(url)
            param_dict = dict([(k, v[0]) for k, v in urlparse.parse_qs(url_parsed.query).items()])
        elif method == 'POST':
            if body == '':
                return param_dict
            # {a:1}
            if re.search(r'^{.*}$', body):
                param_dict = Detector.detect_json(body)
            # body={a:1}
            elif re.search(r'^.*?={.*?}$', body):
                body = re.search(r'^.*?=({.*?})$', body).group()
                param_dict = Detector.detect_json(body)
            # ignore
            elif request.get_header('Content-Type') and 'multipart/form-data; boundary=' in request.get_header(
                    'Content-Type'):
                pass
            elif '&' not in body:
                param_dict = Detector.parse_by_token(body)
                if param_dict:
                    return param_dict
            # a=1&b=2
            else:
                try:
                    if '&' in body:
                        tmp = body.split('&')
                        for i in tmp:
                            try:
                                param, value = i.split('=')[0], i.split('=')[1]
                            except IndexError:
                                pass
                            else:
                                if param not in param_dict:
                                    param_dict[param] = value
                    else:
                        tmp = body.split['=']
                        param_dict = tmp[0], tmp[1]
                except TypeError:
                    print 'Json is not valid:%s' % body
        return param_dict

    @staticmethod
    def make_reg(value):
        js_reg = re.compile('<script.*?>.*?' + re.escape(value) + '.*?</script>', re.S)
        html_reg = re.compile('<.*?>.*?' + re.escape(value) + '.*?</[a-zA-Z]{1,10}?>', re.S)
        tag_reg = re.compile('=\"' + re.escape(value) + '\"|=\'' + re.escape(value) + '\'', re.M)
        # function login(a,b){...};login(param1,param2); param1 and param2 are controllable
        func_reg = re.compile('\\(.*?' + re.escape(value) + '.*?\\)')
        reg_list = [js_reg, html_reg, tag_reg, func_reg]
        return reg_list

    @staticmethod
    def detect_position(response, value):
        """
        Detect where the param is reflected.Inaccurate sometimes.
        :param response:
        :param value:
        :return:
        """
        if len(value) <= 1:
            return
        position = []
        response_data = response.data
        response_code = response.code
        reg_list = Detector.make_reg(value)
        js_reg = reg_list[0]
        html_reg = reg_list[1]
        tag_reg = reg_list[2]
        func_reg = reg_list[3]
        if not response_code.startswith('3'):
            # param reflected in response hreaders.
            # for i in response_headers.values():
            #     if value in i:
            #         position.append('header')
            #         break
            # param reflected in response data.
            if isinstance(response_data, unicode):
                # change unicode to str
                response_data = response_data.encode('utf-8')
            if value in response_data:
                content_type = response.get_header('Content-Type')
                if content_type:
                    # content-type=text/html
                    if 'text/html' in content_type:
                        if not re.search('<html.*?</html>', response_data, re.S):
                            position.append('html')
                        if re.search(js_reg, response_data):
                            # check value's type,str or number
                            type = check_type(value)
                            bs = BeautifulSoup(response_data, 'lxml')
                            script_tag_list = bs.find_all('script')
                            if type == 'string':
                                for i in script_tag_list:
                                    js_code = i.text.encode('utf-8')
                                    # replace ' ' to ''
                                    js_code = js_code.replace(' ', '')
                                    if value in js_code:
                                        if re.search('\'[^\"\']*?' + re.escape(value) + '[^\"\']*?\'', js_code, re.I):
                                            position.append('jssq')
                                        else:
                                            position.append('jsdq')
                            else:
                                for i in script_tag_list:
                                    js_code = i.text.encode('utf-8')
                                    # replace ' ' to ''
                                    js_code = js_code.replace(' ', '')
                                    if value in js_code:
                                        if re.search('\'[^\"]*?' + re.escape(value) + '[^\"]*?\'', js_code, re.I):
                                            position.append('jssq')
                                        if re.search('[+\\-*/%=]{value}[^\"\']*?;|[+\\-*/%=]{value}[^\"\']*?;'.format(
                                                value=re.escape(value)), js_code):
                                            jsnq_match=re.search('[+\\-*/%=]{value}[^\"\']*?;|[+\\-*/%=]{value}[^\"\']*?;'.format(
                                                value=re.escape(value)), js_code).group()
                                            # in json
                                            if re.search(':\"[^\"]*?{value}[^\"]*?\"'.format(value=re.escape(value)),js_code):
                                                pass
                                            # include html escape
                                            elif re.search(r'&amp;$|\\x26amp;$',jsnq_match):
                                                pass
                                            else:
                                                position.append('jsnq')
                                        # func call
                                        # elif re.search(,js_code,re.I):
                                        #     pass
                                        if re.search('\"[^\'\"]{0,}?' + re.escape(value) + '[^\'\"]*?\"', js_code,
                                                     re.I):
                                            position.append('jsdq')
                        if re.search(html_reg, response_data):
                            position.append('html')
                        if re.search(tag_reg, response_data):
                            position.append('tag')
                        func_match = re.search(func_reg, response_data)
                        if func_match:
                            result = func_match.group()
                            # too long means not function call
                            if len(result) < 50:
                                position.append('func')
                    # Content-type=other
                    else:
                        pass
                # have no content-type header
                else:
                    position.append('html')
        else:
            pass
            # print '30x redirect'
        return position


class Processor():
    def __init__(self, traffic_obj):
        """
        Do some preprocess work.
        :param traffic_obj:
        """
        self.request, self.response = traffic_obj[0], traffic_obj[1]
        self.param_dict = {}
        self.reflect = []

    def process_param(self):
        rtn = Detector.detect_param(self.request)
        if rtn:
            self.param_dict = rtn

    @functimeout(30)
    def process_reflect(self):
        for param, value in self.param_dict.items():
            # improve accuracy
            if len(value) > 1:
                position = Detector.detect_position(self.response, value)
                if position:
                    self.reflect.append((param, value, position))
                    # save position=jssq & tag & jsnq & func for analysing.
                    if 'jssq' in position or 'jsnq' in position or 'tag' in position or 'func' in position:
                        reflect_list.append((self.request.url, param, value, position))

    def process_page(self):
        content_type = self.response.get_header('Content-Type')
        if content_type:
            if 'text/html' in content_type and self.response.data:
                self.ispage = True
        else:
            self.ispage = True

    @staticmethod
    def get_process_chains():
        return set(list(
            filter(lambda m: not m.startswith("__") and not m.endswith("__") and callable(getattr(Processor, m)),
                   dir(Processor)))) - {'run', 'get_process_chains', }

    def run(self):
        for i in Processor.get_process_chains():
            func = getattr(self, i)
            try:
                func()
            except Func_timeout_error,e:
                print str(e)+self.request.url


class Scan(Process):
    PAYLOADS = (
        ('html', '<xsshtml></xsshtml>', '<xsshtml></xsshtml>'),
        ('jsdq', 'xssjs";', '<script.*?xssjs";.*?</script>'),
        ('jssq', 'xssjs\';', '<script.*?xssjs\';.*?</script>'),
        ('jsnq', 'xssjs;', '<script.*?xssjs;.*?</script>'),
        ('tag', 'xsstag"', '=xsstag".*?"'),
        # reflected in  js code's comment,less
        # reflected in html's comment,less
        # reflected in function call
    )

    def __init__(self):
        Process.__init__(self)

    def rfxss(self, processor):
        rfxss_case_list = []
        if processor.reflect:
            request = processor.request
            method, url, headers, body = request.method, request.url, request.headers, request.body
            reflect = processor.reflect
            if method == 'GET':
                for i in reflect:
                    param, value, position = i[0], i[1], i[2]
                    for location, payload, match in self.PAYLOADS:
                        if location in position:
                            new_url = change_by_param(url, param, payload)
                            case = Case(vul='Reflected XSS', method='GET', url=new_url, headers=headers, body='',
                                        args=(location, match, param, value))
                            rfxss_case_list.append(case)
                return rfxss_case_list
            elif method == 'POST':
                for i in reflect:
                    param, value, position = i[0], i[1], i[2]
                    for location, payload, match in self.PAYLOADS:
                        if location in position:
                            new_body = body.replace(value, payload)
                            case = Case(vul='Reflected XSS', method='POST', url=url, headers=headers, body=new_body,
                                        args=(location, match, param, value))
                            rfxss_case_list.append(case)
                return rfxss_case_list

    def run(self):
        while True:
            try:
                traffic_obj = traffic_queue.get(timeout=3)
            except Empty:
                print 'traffic_queue is empty!'
                time.sleep(1)
            else:
                print "Scan-%s,TRAFFIC_QUEUE:%s" % (os.getpid(), traffic_queue.qsize())
                if traffic_obj == None:
                    break
                else:
                    processor = Processor(traffic_obj)
                    processor.run()
                    if processor.reflect:
                        rtn = self.rfxss(processor)
                        if rtn and isinstance(rtn, list):
                            case_list.extend(rtn)


class Verify():
    ERROR_COUNT = 0

    @staticmethod
    def verify(response, args):
        match = args[1]
        location = args[0]
        if isinstance(response, unicode):
            content = response
            # test tag
            if location == 'html' and re.search(match, content):
                bs = BeautifulSoup(content, 'lxml')
                xsshtml_tag_list = bs.find_all('xsshtml')
                if xsshtml_tag_list:
                    return True
            elif re.search(match, content, re.S):
                return True
        else:
            content = response.read()
            if location == 'html' and re.search(match, content):
                bs = BeautifulSoup(content, 'lxml')
                xsshtml_tag_list = bs.find_all('xsshtml')
                if xsshtml_tag_list:
                    return True
            elif re.search(match, content, re.S):
                return True

    @staticmethod
    def request_and_verify(case):
        vul = case.vul
        method = case.method
        url = case.url
        headers = case.headers
        body = case.body
        args = case.args
        old_param = args[2]
        old_value = args[3]
        print 'Verify case use:\n%s' % url
        # time out
        with gevent.Timeout(20, False)as t:
            resp = make_request(method, url, headers, body)
            if resp:
                if Verify.verify(resp, args):
                    poc = gen_poc(method, url, body, old_param, old_value)
                    print_warn('Found %s in %s' % (vul, poc))
                    result = (vul, url, poc)
                    return result
            # count++ when error happened
            else:
                Verify.ERROR_COUNT += 1

    @staticmethod
    def verify_async(case_list,coroutine):
        """
        Verify used gevent lib
        :param case_list:
        :param coroutine:
        :return:
        """
        from gevent import monkey
        monkey.patch_all()
        result = []
        geventPool = pool.Pool(coroutine)
        tasks = [geventPool.spawn(Verify.request_and_verify, case) for case in case_list]
        gevent.joinall(tasks)
        for i in tasks:
            if i.value is not None:
                result.append(i.value)
        print_info('Total Verify-Case is: %s, %s error happened.' % (len(case_list), Verify.ERROR_COUNT))
        return result

    class Openner(Process):
        def __init__(self, browser_type, case_list):
            Process.__init__(self)
            self.browser = browser_type
            self.case_list = case_list

        def reload(self, browser):
            # close old
            browser.quit()
            # restart
            if self.browser == 'chrome':
                browser = chrome()
            elif self.browser=='chrome-headless':
                browser=chrome(headless=True)
            else:
                browser = phantomjs()
            # add cookie, the scope is case_list[0].url's top-domain
            add_cookie(browser, case_list[0].url)
            return browser

        def handle_block(self, browser):
            try:
                browser.execute_script('window.open();')
                handlers = browser.window_handles
                browser.switch_to_window(handlers[-1])
            except Exception:
                browser = self.reload(browser)
                return browser

        def run(self):
            blocked_urls = []
            if self.browser == 'chrome':
                browser = chrome()
            elif self.browser=='chrome-headless':
                browser=chrome(headless=True)
            else:
                browser = phantomjs()
            # add cookie, the scope is case_list[0].url's top-domain
            add_cookie(browser, case_list[0].url)
            for case in self.case_list:
                if case.method == 'POST':
                    continue
                vul = case.vul
                url = case.url
                args = case.args
                splited = url.split('/', 3)
                path = '/'.join(splited)
                # if not block
                if path not in blocked_urls:
                    try:
                        browser.get(url)
                    except TimeoutException, e:
                        print e
                        # mark if browser get() exception
                        REQUEST_ERROR.append(('Openner get()', url, 'timeout'))
                        # browser blocked sometimes.
                        rtn = self.handle_block(browser)
                        if rtn is not None:
                            browser = rtn
                            splited = url.split('/', 3)
                            path = '/'.join(splited)
                            blocked_urls.append(path)
                    except BadStatusLine, e:
                        print e
                        REQUEST_ERROR.append(('Render get()', url, 'BadStatusLine'))
                        splited = url.split('/', 3)
                        path = '/'.join(splited)
                        blocked_urls.append(path)
                    except UnicodeDecodeError:
                        pass
                    else:
                        try:
                            page_source = browser.page_source
                        # handle alert
                        except UnexpectedAlertPresentException:
                            alert = browser.switch_to_alert()
                            alert.accept()
                            page_source = browser.page_source
                        if Verify.verify(page_source, args):
                            poc = gen_poc('GET', url, '')
                            result = (vul, url, poc)
                            openner_result.append(result)
            # must close the browser.
            browser.quit()

    @staticmethod
    def verify_with_browser(browser_type, case_list, process_num):
        open_task = []
        i = len(case_list)
        k = 0
        if i > process_num:
            j = i / process_num
            for i in range(process_num):
                if i == process_num - 1:
                    cases = case_list[k:]
                else:
                    cases = case_list[k:j * (i + 1)]
                    k = j * (i + 1)
                t = Verify.Openner(browser_type, cases)
                open_task.append(t)
        else:
            cases = case_list
            t = Verify.Openner(browser_type, cases)
            open_task.append(t)
        for i in open_task:
            i.start()
        for i in open_task:
            i.join()


class Render(Process):
    """
    Render if the page is DOM-based.
    """
    def __init__(self, id, browser, url_list):
        Process.__init__(self)
        self.id = id
        self.url_list = url_list
        self.browser = browser

    def reload(self, browser):
        # close old
        browser.quit()
        # restart
        if self.browser == 'chrome':
            browser = chrome()
        elif self.browser=='chrome-headless':
            browser=chrome(headless=True)
        else:
            browser = phantomjs()
        # add cookie, the scope is case_list[0].url's top-domain
        add_cookie(browser, self.url_list[0])
        return browser

    def handle_block(self, browser):
        try:
            browser.execute_script('window.open();')
            handlers = browser.window_handles
            browser.switch_to_window(handlers[-1])
        except Exception:
            browser = self.reload(browser)
            return browser

    def gen_traffic(self, url, page_source, response_headers):
        if self.browser == 'chrome' or self.browser=='chrome-headless':
            request = HttpRequest(method='GET', url=url, headers=Traffic_generator.DEFAULT_HEADER, body='')
            if not response_headers:
                # default content-type is text/html
                response_headers = {'Content-Type':'text/html'}
            response = HttpResponse(code='200', reason='OK', headers=response_headers,
                                    data=page_source)
            return (request, response)
        elif self.browser == 'phantomjs':
            request = HttpRequest(method='GET', url=url, headers=Traffic_generator.DEFAULT_HEADER, body='')
            if not response_headers:
                response_headers = {'Content-Type':'text/html'}
            response = HttpResponse(code='200', reason='OK', headers=response_headers,
                                    data=page_source)
            return (request, response)

    def run(self):
        blocked_urls = []
        if self.browser == 'chrome':
            browser = chrome()
        elif self.browser=='chrome-headless':
            browser=chrome(headless=True)
        else:
            browser = phantomjs()
        # add cookie, the scope is url_list[0]'s top-domain
        add_cookie(browser, self.url_list[0])
        for url in self.url_list:
            splited = url.split('/', 3)
            path = '/'.join(splited)
            # if not block
            if path not in blocked_urls:
                try:
                    browser.get(url)
                except TimeoutException, e:
                    print e
                    # save if browser get() exception
                    REQUEST_ERROR.append(('Render get()', url, 'timeout'))
                    # browser blocks sometimes.
                    rtn = self.handle_block(browser)
                    if rtn is not None:
                        browser = rtn
                        splited = url.split('/', 3)
                        path = '/'.join(splited)
                        blocked_urls.append(path)
                except BadStatusLine, e:
                    print e
                    REQUEST_ERROR.append(('Render get()', url, 'BadStatusLine'))
                    splited = url.split('/', 3)
                    path = '/'.join(splited)
                    blocked_urls.append(path)
                except UnicodeDecodeError:
                    pass
                else:
                    try:
                        page_source = browser.page_source
                    # handle alert
                    except UnexpectedAlertPresentException:
                        alert = browser.switch_to_alert()
                        alert.accept()
                        page_source = browser.page_source
                    response_headers = getResponseHeaders(self.browser, browser)
                    traffic = self.gen_traffic(url, page_source, response_headers)
                    if traffic:
                        traffic_list.append(traffic)
        # quit browser.
        browser.quit()

def url_filter(url):
    if '?' not in url:
        return False
    # filter static URL
    if static_reg.search(url):
        return False
    else:
        api = get_api(url)
        # check if the api is exists
        if api in api_list:
            return False
        else:
            api_list.append(api)
            return url

class Engine(object):
    def __init__(self, id, url, file, burp, process, coroutine,browser,filter):
        self.id = id
        self.url = url
        self.file = file
        self.burp = burp
        self.process = process
        self.coroutine=coroutine
        self.browser = browser
        self.filter=filter

    def put_queue(self):
        traffic_path = []
        files = os.listdir(TRAFFIC_DIR)
        for i in files:
            if re.search(self.id + '.traffic\d*', i):
                traffic_path.append(os.path.join(TRAFFIC_DIR, i))
        for i in traffic_path:
            with open(i)as f:
                traffic_list = cPickle.load(f)
                print 'Start to put traffic( used %s) into traffic_queue,Total is %s.' % (i, len(traffic_list))
                for traffic in traffic_list:
                    traffic_queue.put(traffic)

    def send_end_sig(self):
        for i in range(self.process):
            traffic_queue.put(None)

    def put_burp_to_trafficqueue(self):
        """
        parse xxx.xml from burpsuite proxy.
        :return:
        """
        if os.path.exists(self.burp):
            import base64
            from xml.etree import cElementTree as ET
            from model import HttpRequest, HttpResponse
            with open(self.burp)as f:
                xmlstr = f.read()
            try:
                root = ET.fromstring(xmlstr)
            except cElementTree.ParseError,e:
                print 'Parse burpsuite data error: '+str(e)
                exit(0)
            for child in root:
                if child.tag == 'item':
                    req_headers = {}
                    resp_headers = {}
                    code = ''
                    request, response = '', ''
                    for child2 in child:
                        if child2.tag == 'method':
                            method = child2.text
                        if child2.tag == 'url':
                            url = child2.text
                            # static url in burp
                            if static_reg.search(url):
                                break
                        if child2.tag == 'status':
                            code = child2.text
                        if child2.tag == 'request':
                            req_text = child2.text
                            # base64 decode
                            req_text = base64.b64decode(req_text)
                            headers_list = req_text.split('\r\n\r\n', 1)[0].split('\r\n')[1:]
                            for header in headers_list:
                                try:
                                    header_key, header_value = header.split(': ')[0], header.split(': ')[1]
                                    if header_key not in req_headers.keys():
                                        req_headers[header_key] = header_value
                                # split header error
                                except IndexError,e:
                                    print e
                            body = req_text.split('\r\n\r\n', 1)[1]
                            request = HttpRequest(method, url, req_headers, body)
                        if child2.tag == 'response':
                            resp_text = child2.text
                            # if response is not None
                            if resp_text:
                                # base64 decode
                                resp_text = base64.b64decode(resp_text)
                                reason = resp_text.split('\r\n')[0]
                                headers_list = resp_text.split('\r\n\r\n', 1)[0].split('\r\n')[1:]
                                for header in headers_list:
                                    header_key, header_value = header.split(': ')[0], header.split(': ')[1]
                                    if header_key not in resp_headers.keys():
                                        resp_headers[header_key] = header_value
                                data = resp_text.split('\r\n\r\n', 1)[1]
                                response = HttpResponse(code, reason, resp_headers, data)
                    if request and response:
                        if request.method == 'GET' and '?' in request.url:
                            # filter static URL
                            if not static_reg.search(url):
                                burp_traffic.append((request, response))
                                traffic_queue.put((request, response))
                        elif request.method == 'POST' and request.body:
                            content_type=request.get_header('Content-Type')
                            # save multipart
                            if content_type and 'multipart/form-data; boundary=' in content_type:
                                MULTIPART.append((request, response))
                            else:
                                burp_traffic.append((request, response))
                                traffic_queue.put((request, response))
        else:
            print '%s not exists!' % self.burp

    @staticmethod
    def get_traffic_path(id):
        traffic_path = os.path.join(TRAFFIC_DIR, id + '.traffic')
        return traffic_path

    def get_render_task(self, url_list):
        render_task = []
        i = len(url_list)
        k = 0
        if i > self.process:
            j = i / self.process
            for i in range(self.process):
                if i == self.process - 1:
                    urls = url_list[k:]
                else:
                    urls = url_list[k:j * (i + 1)]
                    k = j * (i + 1)
                t = Render(self.id, self.browser, urls)
                render_task.append(t)
        else:
            urls = url_list
            t = Render(self.id, self.browser, urls)
            render_task.append(t)
        return render_task

    def deduplicate(self, url_list):
        print 'Start to deduplicate for all urls.'
        filtered_path = self.file + '.filtered'
        if os.path.exists(filtered_path):
            print '%s has been filtered as %s.' % (self.file, filtered_path)
            with open(filtered_path)as f:
                filtered = f.read().split('\n')
                return filtered
        filtered = []
        # result = map(filter, url_list)
        from multiprocessing import cpu_count
        from multiprocessing.pool import Pool
        p=Pool(cpu_count())
        result=p.map(url_filter,url_list)
        for i in result:
            if isinstance(i, str):
                filtered.append(i)
        with open(filtered_path, 'w') as f:
            f.write('\n'.join(filtered))
        print 'Saved filtered urls to %s.' % filtered_path
        return filtered

    def save_reflect(self):
        if len(reflect_list) > 0:
            saved_list = [i for i in reflect_list]
            reflect_path = self.get_traffic_path(self.id).replace('.traffic', '.reflect')
            if os.path.exists(reflect_path):
                pass
            else:
                with open(reflect_path, 'w') as f:
                    cPickle.dump(saved_list, f)

    @staticmethod
    def save_traffic(traffic_obj_list, id, piece=3000):
        """

        :param traffic_obj_list:
        :param id: task id
        :param piece: default 3000 per piece
        :return:
        """
        traffic_path = Engine.get_traffic_path(id)
        if len(traffic_obj_list) > 0:
            saved_traffic_list = [i for i in traffic_obj_list]
            # slice traffic if too large
            if len(saved_traffic_list) > piece:
                traffic_divided_path = []
                traffic_divided = divide_list(saved_traffic_list, piece)
                for i in range(len(traffic_divided)):
                    traffic_divided_path.append(traffic_path + str(i))
                    with open(traffic_path + str(i), 'w')as traffic_f:
                        cPickle.dump(traffic_divided[i], traffic_f)
                print_info('Traffic of %s has been divided and saved to %s.' % (id, ','.join(traffic_divided_path)))
            else:
                with open(traffic_path, 'w')as traffic_f:
                    cPickle.dump(saved_traffic_list, traffic_f)
                    print_info('Traffic of %s has been saved to %s.' % (id, traffic_path))

    def save_request_exception(self):
        if len(REQUEST_ERROR) > 0:
            with open(self.get_traffic_path(self.id).replace('.traffic', '.error'), 'w')as f:
                cPickle.dump(REQUEST_ERROR, f)

    def save_redirect(self):
        if len(REDIRECT) > 0:
            with open(self.get_traffic_path(self.id).replace('.traffic', '.redirect'), 'w')as f:
                cPickle.dump(REDIRECT, f)

    def save_multipart(self):
        if len(MULTIPART) > 0:
            with open(self.get_traffic_path(self.id).replace('.traffic', '.multipart'), 'w')as f:
                cPickle.dump(MULTIPART, f)

    def save_analysis(self):
        print_info('Total multipart is: %s,redirect is: %s,request exception is: %s' % (
        len(MULTIPART), len(REDIRECT), len(REQUEST_ERROR)))
        self.save_multipart()
        self.save_redirect()
        self.save_request_exception()

    def urldecode(self, url_list):
        for i in range(len(url_list)):
            if '%' in url_list[i]:
                url_list[i] = urllib.unquote(url_list[i])
        return url_list

    @staticmethod
    def is_scanned(id):
        files = os.listdir(TRAFFIC_DIR)
        for i in files:
            if re.search(id + '\.traffic\d', i):
                return True

    def start(self):
        # check if traffic_path exists.
        if self.is_scanned(self.id):
            print 'Task %s has been scanned,Rescan.' % self.id
            self.put_queue()
            self.send_end_sig()
        elif self.burp:
            self.put_burp_to_trafficqueue()
            self.send_end_sig()
            # save burp traffic
            if burp_traffic:
                self.save_traffic(burp_traffic, self.id)
        else:
            if self.url != '':
                url_list = [self.url]
            elif self.file:
                if os.path.exists(self.file):
                    with open(self.file)as f:
                        url_list = []
                        temp = [url.strip() for url in f.read().split('\n')]
                        for i in temp:
                            if i:
                                url_list.append(i)
                        if not self.file.endswith('.slice'):
                            url_list = self.deduplicate(url_list)
                        if self.filter:
                            exit(0)
                        # test 10000 urls
                        # url_list = url_list[:100]
                else:
                    print '%s not exists!' % self.file
                    exit(0)
            # decode
            url_list = self.urldecode(url_list)
            if self.browser:
                # render
                print 'Start to request url with %s.' % self.browser
                render_task = self.get_render_task(url_list)
                for i in render_task:
                    i.start()
                for i in render_task:
                    i.join()
                self.save_traffic(traffic_list, self.id)
                # put traffic tp queue
                for i in range(len(traffic_list)):
                    request = traffic_list[i][0]
                    response = traffic_list[i][1]
                    traffic_queue.put((request, response))
                self.send_end_sig()
            else:
                # traffic genetator
                print 'Start to request url with urllib2.'
                traffic_maker = Traffic_generator(self.id, url_list,self.coroutine)
                traffic_maker.start()
                traffic_maker.join()
                self.put_queue()
                self.send_end_sig()
        # scan
        task = [Scan() for i in range(self.process)]
        for i in task:
            i.start()
        for i in task:
            i.join()
        # save reflect for analyzing
        self.save_reflect()
        if case_list:
            if self.browser:
                # verify
                Verify.verify_with_browser(self.browser, case_list, self.process)
                self.save_analysis()
                return openner_result
            else:
                # verify,async
                verify_result = Verify.verify_async(case_list,self.coroutine)
                self.save_analysis()
                return verify_result

if __name__ == '__main__':
    pass