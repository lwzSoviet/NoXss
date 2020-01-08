#!/usr/bin/python2.7
# -*- encoding: utf-8 -*-
"""
    @Description: Models used.

    ~~~~~~
    @Author  : longwenzhang
    @Time    : 19-8-19   3:13
"""
import json

class HttpRequest():
    def __init__(self,method,url,headers,body=''):
        self.method=method
        self.url=url
        self.headers=headers
        self.body=body

    def tostring(self):
        return self.method+self.url+json.dumps(self.headers,encoding='utf-8')+self.body

    def get_header(self,header_name):
        # Host
        if header_name in self.headers.keys():
            return self.headers[header_name]
        # host=Host
        elif header_name.lower() in self.headers.keys():
            return self.headers[header_name.lower()]

    def change_header(self,header_name,tovalue):
        # Host
        if header_name in self.headers.keys():
            self.headers[header_name]=tovalue
        # host=Host
        elif header_name.lower() in self.headers.keys():
            self.headers[header_name.lower()]=tovalue

    @staticmethod
    def headers2print(headers):
        headersprint=''
        for key,value in headers.items():
            headersprint+=key
            headersprint+=': '
            headersprint+=value
            headersprint+='\n'
        return headersprint

    def headers2str(self):
        headerstr=''
        for key,value in self.headers.items():
            headerstr+=key
            headerstr+=': '
            headerstr+=value
            headerstr+='\n'
        return headerstr

    def __str__(self):
        return self.method+' '+self.url+'\n'+self.headers2print(self.headers)+'\n'+self.body

class HttpResponse():
    def __init__(self,code,reason,headers,data):
        self.code=code
        self.reason=reason
        self.headers=headers
        self.data=data

    def tostring(self):
        return self.code+self.reason+json.dumps(self.headers,encoding='utf-8')+self.data

    def get_header(self,header_name):
        if header_name in self.headers.keys():
            return self.headers[header_name]
        elif header_name.lower() in self.headers.keys():
            return self.headers[header_name.lower()]

    def get_setcookie_list(self):
        setcookie_list=[]
        for resp_header_name,resp_header_value in self.headers.items():
            if resp_header_name=='Set-Cookie':
                setcookie_list.append(resp_header_value)
        return setcookie_list

    def __str__(self):
        return self.code+' '+self.reason+'\n'+HttpRequest.headers2print(self.headers)+'\n'+self.data

class Case():
    def __init__(self,vul,method,url,headers,body,args):
        """
        Case class is a object like test case,include http-util,verify function,url etc.
        :param vul:
        :param method:
        :param url:
        :param headers:
        :param body:
        :param args: (location,match)
        """
        self.vul = vul
        self.method = method
        self.url = url
        self.headers=headers
        self.body = body
        self.args=args

if __name__ == '__main__':
    pass