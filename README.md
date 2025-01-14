<h1 align="center">
    <img src="https://i.jpg.dog/file/jpg-dog/9160396e547d9abde7ec3199c571aa47.png" alt="SSRSpeedN" width="240">
</h1>
<p align="center">
Batch speed measuring tool based on Shadowsocks(R) and V2Ray
</p>
<p align="center">
  <a href="https://github.com/PauperZ/SSRSpeedN/tags"><img src="https://img.shields.io/github/tag/PauperZ/SSRSpeedN.svg"></a>
  <a href="https://github.com/PauperZ/SSRSpeedN/releases"><img src="https://img.shields.io/github/release/PauperZ/SSRSpeedN.svg"></a>
  <a href="https://github.com/PauperZ/SSRSpeedN/blob/master/LICENSE"><img src="https://img.shields.io/github/license/PauperZ/SSRSpeedN.svg"></a>
</p>

## 注意事项

- 测速及解锁测试仅供参考，不代表实际使用情况，由于网络情况变化、Netflix封锁及ip更换，测速具有时效性

- 本项目使用 [Python](https://www.python.org/) 编写，使用前请完成环境安装
- 首次运行前请执行 开始测速.bat 安装pip及相关依赖，也可使用 pip install -r requirements.txt 命令自行安装
- logs文件夹用于记录测速日志，包含节点的详细信息及测速订阅，非必要请勿泄露
- 执行 开始测速.bat 批处理命令即可测速，测速结果保存在 results 文件夹下，不过大佬喜欢用命令行测也可以
- 因为需要依赖 Python 环境，且本项目仍在测试阶段，可能存在部分 bug ，可到 Issues 下进行反馈。
- Netflix 解锁测速结果说明:
```text
Full Native             原生全解锁 
Full Dns                DNS 全解锁
Only original           仅解锁自制剧
None                    未解锁
其中原生解锁和DNS解锁只是解锁方式有区别，实际体验区别不大，在电视端使用时DNS解锁可能会提示使用代理。
```
- UDP NAT 结果说明:
```text
Full-cone NAT                      全锥形 NAT
Symmetric NAT                      对称型 NAT
Restricted Cone NAT                限制锥形 NAT (IP 受限)                                                                                                                       
Port-Restricted Cone NAT           端口限制锥形 NAT (IP 和端口都受限)
Blocked                            未开启UDP
其中全锥型的穿透性最好，而对称型的安全性最高，如果要使用代理打游戏，节点的 UDP NAT 类型最好为全锥型，其次为对称型，尽量不要用其他 NAT 类型的节点玩游戏
```

## 特性

本项目在原 SSRSpeed (已跑路) 的基础上，集成了如下特性

- 支持 Shadowsocks(R) / Vless / Vmess / Trojan 协议
- 支持单线程/多线程同时测速，可以同时反映视频播放/多线程下载等场景的节点速度
- 支持 fast.com / YOUTUBE 码率等多种测速方式（仅限 Windows）
- 支持 Netflix 解锁测试，分为 原生全解锁 / DNS全解锁 / 仅解锁自制剧 / 无解锁 四档
- 支持 流媒体平台 Abema/Bahamut 动画疯/Bilibili/Disney+/HBO max/TVB/YouTube premium/chatgpt 的解锁测试
- 配置文件中提供了测速模块的控制端，可以自由选择是否测速/测ping/检测流媒体解锁
- 取消了原版的大红配色，默认为彩虹配色，并增加了新配色 (poor)
- 增加了节点复用检测功能
- 增加了实际流量倍率测试功能
- 完善了对Linux的支持，并提供了docker镜像可以用来进行节点状态监控
- 移除了赞助频道tag，如果有频道赞助请务必联系我！

## 相关依赖

Python第三方库
见 `requirements.txt`

Linux 依赖

- [libsodium](https://github.com/jedisct1/libsodium)
- [Shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev)
- [Simple-Obfs](https://github.com/shadowsocks/simple-obfs)

## 支持平台

### 已测试平台

1. Windows 10 x64
2. Ubuntu 22.04.3 LTS
3. Docker

其他平台需要测试，欢迎反馈

### 理论支持平台

支持 Python 及 Shadowsocks, ShadowsocksR, V2Ray, Trojan 的平台

## 使用指南

### 批处理测速
使用管理员身份运行`开始测速.bat`

### 命令行测速

安装第三方库:

~~~~bash
pip install -r requirements.txt
~~~~

测速主程序及附加选项：

~~~~text
python ./main.py
Usage: main.py [options] arg1 arg2...

附加选项:
  --version             输出版本号并退出
  -h, --help            输出帮助信息并退出
  -c GUICONFIG, --config=GUICONFIG
                        通过节点配置文件加载节点信息.
  -u URL, --url=URL     通过节点订阅链接加载节点信息.
  --include             通过节点标识和组名筛选节点.
  --include-remark      通过节点标识筛选节点.
  --include-group       通过组名筛选节点.
  --exclude             通过节点标识和组名排除节点.
  --exclude-group       通过组名排除节点.
  --exclude-remark      通过节点标识排除节点.
  --use-ssr-cs          替换SSR内核 ShadowsocksR-libev --> ShadowsocksR-C# (Only Windows)
  -g GROUP              自定义测速组名.
  -y, --yes             跳过节点信息确认（我嫌那玩意太麻烦设成默认了）.
  -C RESULT_COLOR, --color=RESULT_COLOR
                    设定测速结果展示配色.
  -S SORT_METHOD, --sort=SORT_METHOD
                        选择节点排序方式 按速度排序/速度倒序/按延迟排序/延迟倒序
                        [speed,rspeed,ping,rping],默认不排序.
  -i IMPORT_FILE, --import=IMPORT_FILE
                        提供给不会p图的同学，偷偷改结果的json文件后重新输出结果.
  --skip-requirements-check
                        跳过确认.
  --debug               采用debug模式.
~~~~

使用样例 :

~~~~text
python main.py -c gui-config.json --include 韩国 --include-remark Azure --include-group YoYu
python main.py -u "https://home.yoyu.dev/subscriptionlink" --include 香港 Azure --include-group YoYu --exclude Azure
~~~~

### docker运行节点状态监控
首先构建docker镜像
```
docker build -t SSRSpeedN .
```
之后使用下面的命令启动docker镜像
```
docker run -d --name SSRSpeedNContainer \
-e CRON_FREQUENCY="*/60 * * * *" \
-v /path/to/subscription:/app/subscription \
-v /path/to/results:/app/results \
-v /path/to/logs:/app/logs \
SSRSpeedN
```
可以手动修改`CRON_FREQUENCY`配置运行频率，详见 [crontab guru](https://crontab.guru/)

当作节点健康探针使用时，建议关闭`speed`、`geoip`等选项节省流量并加快测试速度，避免频繁测速被ban

命令里的subscription、results、logs文件夹可以按需要挂载出来。各文件夹作用如下：
- subscription: 用于存放节点信息。将base64解码后的信息存储到`subscription\subscription`文件里即可，用换行分割
```
ss://xxxxx
ss://xxxxx
vmess://xxxxx
```
- results：用于保存测速结果
- logs：用于保存日志信息

## 自定义配置

- **自定义颜色**
  - 在 ssrspeed_config.json 文件`exportResult`字段下，采用速度（MB/s）对应输出颜色 （RGB 256）方式
- **自定义字体**
  - 下载字体文件放入 /resources/fonts/ 文件夹下，修改 ssrspeed_config.json 文件下第 34 行，本项目自带两个字体
- **修改测速项目**
  - 在 ssrspeed_config.json 文件里，可以设置是否进行ping/Google ping/udp类型/各种流媒体解锁测试
  ```jsonc
	"ntt": { "enabled": true,"internal_ip": "0.0.0.0","internal_port": 54320 }, // UDP 类型测试
	"ping": false, // 是否测试 ping
	"gping": true, // 是否测试 Google ping
	"speed": false, // 是否测速
	"method": "SOCKET", // 测速方式，支持SOCKET / YOUTUBE / NETFLIX
	"StSpeed": false, // 测速方式：单/多线程
    "stream": true, // 是否测试流媒体解锁
	"netflix": true, // 是否测试 Netflix 解锁
	"hbo": false, // 是否测试 HBO max 解锁
	"disney": false, // 是否测试 Disney+ 解锁
	"youtube": false, // 是否测试 YouTube premium 解锁
	"abema": false, // 是否测试 Abema 解锁
	"bahamut": false, // 是否测试 Bahamut (动画疯) 解锁
	"bilibili": false, // 是否测试 Bilibili 解锁
	"tvb": false, // 是否测试 TVB 解锁
	"chatgpt": true, // 是否测试 chatgpt 解锁
	"geoip": false, // 是否测试落地出口
	"multiplex":false, // 是否测试单线复用
  ```

- **修改测速方式**
  - 在 ssrspeed_config.json 文件下第 24 行，可以设置采用单/多线程测速方式或均速/最高速测速方式，默认为前者 

## 致谢

- 原作者
  - [NyanChanMeow](https://github.com/NyanChanMeow)
  - [PauperZ](https://github.com/PauperZ/SSRSpeedN)
- beta版测试
  - [ChenBilly](https://t.me/ChenBilly)
  - [Duang](https://t.me/duang11212)
  - [万有引力](https://t.me/cloudspeedtest)
- 建议及支持
  - [jiexi](https://t.me/jiexi001)
  - [萌新黑客](https://t.me/yxkumad)
- 原赞助者
  - [便宜机场测速](https://t.me/cheap_proxy)