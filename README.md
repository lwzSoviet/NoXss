# NoXss  

![found](https://img.shields.io/badge/found-200%2B%20xss-red)
[![issues](https://img.shields.io/github/issues/lwzSoviet/NoXss)](https://github.com/lwzSoviet/NoXss/issues)
[![release](https://img.shields.io/badge/release-v1.0--beta-blue)](https://github.com/lwzSoviet/NoXss/releases)
[![license](https://img.shields.io/github/license/lwzSoviet/NoXss)](https://github.com/lwzSoviet/NoXss/blob/master/LICENSE)

NoXss is a cross-site script vulnerability scanner supported reflected xss and dom-based xss. It's very fast and suitable for testing millions of urls. It has found some xss vulnerabilities in Bug Bounty program. 
# Features
+ Fast and suitable for testing millions of urls
+ Support Dom-based xss(use Chrome or Phantomjs) and reflected xss
+ Only use 8 Payloads based on injection postion now(not fuzz,more accurate,faster)
+ Async request(use gevent) and Multi-processed
+ Support single url,file and traffic from Burpsuite
+ Traffic filter based on interface
+ Support speicial headers(referer,cookie,customized token,e.g.)
+ Support rescan quickly by id
# Directory
```
├── engine.py
├── logo
├── cookie.py
├── url.txt
├── cookie
│   └── test.com_cookie
├── traffic
│   ├── 49226b2cbc77b71b.traffic    #traffic file(pickled)
│   └── 49226b2cbc77b71b.reflect    #reflected file(pickled)
├── config.py
├── start.py
├── url.txt.filtered    #filtered urls
├── util.py
├── README.md
├── banner.py
├── requirements.txt
├── result
│   └── 49226b2cbc77b71b-2019_10_29_11_24_44.json   #result
├── model.py
└── test.py
```
# Screenshot 
![s1](https://github.com/lwzSoviet/download/blob/master/images/s1.png)  
# Environment
Linux  
Python2.7  
Browser:Phantomjs or Chrome
# Install
### Ubuntu
+ 1.`apt-get install flex bison phantomjs`
+ 2.`pip install -r requirements.txt`
### Centos
+ 1.`yum install flex bison phantomjs`
+ 2.`pip install -r requirements.txt`
### MacOS
+ 1.`brew install grep findutils flex phantomjs`
+ 2.`pip install -r requirements.txt`  
-----
*If you want to scan use "--browser=chrome",you must install chrome mannually. You can use "--check" to test the installation.*  
`python start.py --check`
# Usage
```
python start.py --url url --save
python start.py --url url --cookie cookie --browser chrome --save  
python start.py --file ./url.txt --save  
python start.py --burp ./test.xml --save
```
### Options    
**--url**&emsp;scan from url.  
**--id**&emsp;rescan from *.traffic file by task id.  
**--file**&emsp;scan urls from text file(like ./url.txt).  
**--burp**&emsp;scan *.xml(base64 encoded,like ./test.xml) from burpsuite proxy.  
**--process**&emsp;number of process.  
**--coroutine**&emsp;number of coroutine.    
**--cookie**&emsp;use cookie.  
**--browser**&emsp;use browser(chrome or phantomjs) to scan,it's good at DOM-based xss but slow.  
**--save**&emsp;save results to ./result/id.json.
### How to scan data from Burpsuite
In Proxy,"Save items" ==> "test.xml"  
![s3](https://github.com/lwzSoviet/download/blob/master/images/s3.png)  
Then you can scan test.xml:  
`python start.py --burp=./test.xml`
### How to rescan
After scanning firstly,there will be taskid.traffic and taskid.reflect in ./traffic/:  
+ taskid.traffic: Web traffic of request(pickled).
+ taskid.reflect: Reflected result (pickled)that included reflected params,reflected position,type and others.  
NoXss will use these middle files to rescan:  
`python start.py --id taskid --save`
# How does NoXss work?
### Payloads
NoXss use only 8 payloads for scanning.These payloads are based on param's reflected position.Fewer payloads make it faster than fuzzing.
### Async&multi-process
NoXss is highly concurrent for using coroutine.
### Support dom-based xss
More and more page is using dom to render html.NoXss can parse it with using Phantomjs(default) or chrome.   
### Analysis files
Some xss is difficult to scan.NoXss will save some files in traffic/ for analysing,include:
+ *.traffic(traffic file during scanning)
+ *.reflect(param's reflected result)
+ *.redirect(30x response)
+ *.error(some error happened such as timeout,connection reset,etc.)
+ *.multipart(when request is multupart-formed,not easy to scan)
# Example
As you see in [Screenshot](https://github.com/lwzSoviet/NoXss#screenshot),the poc is `https://xxx/?proxyAccount=xssjs%22%3B&shareName=duhxams`,That means use the payload `xssjs%22%3B` in param "proxyAccount":  
![poc](https://github.com/lwzSoviet/download/blob/master/images/poc.png)  
Then you can end the double qoutes use payload `xssjs";alert(1);//`.The final exploit is:  
`https://xxx.com/?proxyAccount=xssjs";alert(1);//&shareName=duhxams`  
