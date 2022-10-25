# Nsfocus UTS 实时监测脚本

## 目的

本脚本的目的在于在保障期间自动抓取 UTS 报告并过滤出有价值的条目进行报警。

个人的开发场景时，客户的防火墙没有屏蔽国外地址功能，只能检测到攻击后进行屏蔽。在保障期间，非中国IP发起的危险行为也经常需要注意。而UTS中内网业务行为除法过多警告，但并不想关闭规则，就需要在UTS的众多条目中抓取有价值的信息及时响应。因此，才编写了这个脚本自动抓取最新告警条目并进行过滤。

## 功能

- 检测所有条目内源目地址是否有非中国IP，否则输出该条目并警告。
- 用IP前缀过滤白名单内的告警条目，不予输出。
- 在本地开启 UDP Server 广播输出到特定接口，支持简单异或加密。
- 自行编写python自定义规则（在`LogFilter.py`下）。

## 使用说明

使用此程序需要有抓包/网络监控基础（如使用F12浏览器开发者控制台）观察请求头、Cookie，详细配置需要观察后端返回的威胁告警条目数据。

### 配置文件

`main.py` 是程序入口点，第一次运行会在目录下生成 `config.ini`。想要让程序正常运行，需要先配置文件。一个默认的配置文件如下：

```ini
[config]
; 默认检测时长，不建议超过240s，防止token超时失效。
check_duration = 120
; IP数据库路径
xdb_path = ./ip2region/ip2region.xdb
; UTS管理页面域名
domain = 127.0.0.1
; 过滤后有输出时是否输出响铃符'\a'
bell_when_alert = 1

; 和登录有关的参数，必填
[session]
; 请在这里填写 Cookie 中的 csrftoken
csrftoken = None
; 请在这里填写请求头中的 Authorization
authorization = None

[udp server]
; 是否开启UDP Server功能
enable = 0
; 广播端口
port = 10517
; 广播网络接口地址
broadcast_addr = 127.0.0.1
; 使用的密码，如果为空则不加密
simple_password =

; IP地址白名单
[ip_suffix_whitelist]
0. = 
10. = 
172.16. = 
192.168. = 

; 告警类型白名单
[alert_type_whitelist]
ftp服务用户弱口令认证 = 

```

1. 需要正常登录UTS后，用F12开发者控制台-网络获取两个参数：请求头中的 `Authorization`，和 Cookie 中的 `csrftoken`，然后填写到配置文件中的 `[session]` 节中，来维持登陆状态。

   > 为什么不能直接填写账户密码登录呢？因为作者很弱，难以解析经过压缩和混淆过的 webpack js 代码，目前仅已知 web 登陆界面密码使用 sm2 算法加密，但使用 python 的 gmssl sm2 实现，无法正常登录。如果有能力，希望能够得到指教，甚至是 Pull request。

2. 在 `[config]` 节配置正确的 xdb 路径、UTS Web 域名（`http://{域名}/xxx`）。

3. 自定义自己需要的白名单列表。程序会读取该节 `section` 下的所有选项 `options`，而不管其值如何。
   > 因此，默认的配置文件读取到的IP前缀白名单是 `["0.", "10.", "172.16.", "192.168."]`。

### 开始运行脚本

运行 `python main.py`。

### UDP 服务器

当 `[udp server] enable = 1` 时，UDP 服务器会启动，在每一次打印时会发送 UDP 广播信息。在 UDP 客户端，运行 `udp_server/udp_client.py` 即可。

唯一值得注意的是，如果服务端密钥不为空，那么需要修改 `udp_client.py` 文件，在里面填写密钥。

### 告警类型白名单

未修改过滤代码的默认情况下，未在白名单中的告警条目会被输出。在白名单中的行为，如果源IP符合IP前缀白名单，则不输出；否则，则输出。总的来说，白名单只过滤同时符合这两个条件的条目：源IP前缀符合IP前缀白名单、告警信息在自定义的告警类型白名单中。

告警类型，是每个后端返回的告警条目对象中的 `msg` 属性。

## 其他

我也想不起来啥其他了，有啥想说的搞 issue！
