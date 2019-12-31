#!/usr/bin/python2.7
# -*- encoding: utf-8 -*-
"""
    @Description: Cli
    
    ~~~~~~ 
    @Author  : longwenzhang
    @Time    : 19-10-9  10:13
"""
import argparse
from multiprocessing import cpu_count
from banner import banner
from engine import Engine
from util import print_info, save, gen_id, get_domain_from_url

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog="start.py",description='scan xss from url or file.',usage='start.py --url=url --save')
    parser.add_argument('-v','--version', action='version', version='V1.0-beta')
    parser.add_argument('--check', action='store_true', help='check if browser is installed correctly.')
    parser.add_argument('--url','-u',help='the target site of scan.')
    parser.add_argument('--id',action='store',help='rescan by task id.')
    parser.add_argument('-f','--file',help='scan urls from text file.')
    parser.add_argument('--burp', help='scan from *.xml from burpsuite proxy.')
    parser.add_argument('--process',type=int,help='process number.')
    parser.add_argument('-c','--coroutine',type=int,help='coroutine number.')
    parser.add_argument('--cookie',action='store',help='use cookie.')
    parser.add_argument('--filter', action='store_true', help='filter urls when use --file.')
    parser.add_argument('--browser',action='store',help='scan with browser,is good at Dom-based xss but slow.')
    parser.add_argument('--save',action='store_true',help='save result to json file.')
    banner()
    args=parser.parse_args()
    if args.check:
        from check import check_install
        check_install()
    # default
    url,file,burp='','',''
    filter=False
    # default use number of cpu-core as processes
    num=cpu_count()
    # default
    coroutine=200
    if args.url:
        from check import check_url
        url=args.url
        num=1
        check_url(url)
    if args.file:
        file=args.file
    if args.burp:
        burp=args.burp
    browser=''
    if args.browser:
        browser=args.browser
        # default 2 if use browser
        num=2
        if args.url:
            num=1
    if args.process:
        num=args.process
    if args.coroutine:
        coroutine=args.coroutine
    if args.cookie:
        from cookie import save_cookie_ip, is_ip
        if file:
            with open(file)as f:
                scope_url=f.readline().strip()
        elif url:
            scope_url=url
        domain=get_domain_from_url(scope_url)
        if is_ip(scope_url):
            save_cookie_ip(args.cookie, domain)
        else:
            from cookie import save_cookie
            save_cookie(args.cookie, domain)
    if url or file or burp or args.id or args.filter:
        if args.id:
            id=args.id
            if not Engine.is_scanned(id):
                print 'Task %s not found,exit.'
                exit(0)
        else:
            id=gen_id()
        engine=Engine(id=id,url=url,file=file,burp=burp,process=num,browser=browser,coroutine=coroutine,filter=filter)
        result=engine.start()
        if result:
            save(result,id)
        else:
            print_info('No xss found!')
    else:
        print 'error: missing a mandatory option (--url, --file, --burp, --id)!'