# flowscan
通过管道(|)串联来完成各种自定义扫描（`sudo ./flowscan masscan -i 192.168.10.1 | ./flowscan nmap -d`）：
```
端口存活探测：masscan (syn无状态扫描,需要root权限)
             tcpscan（tcp扫描）
端口指纹探测:nmap (先用httpx识别是否为http协议如果能访问协议识别成功、否则使用nmap识别) (指纹包含nmap的probes协议指纹、Ehole网站指纹[默认开启]、wappalyzer开源的网站指纹[默认关闭-d参数开启])
服务弱口令爆破:crack
poc扫描：poc（使用了afrog的poc，可配合指纹扫描，匹配规则为插件名或者插件id包含是否指纹名称）
```

支持（IP、域名、IP:PORT、域名:PORT、URL、域名:8000+IP）等输入
## 用法
```
Usage: flowscan <command>

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  nmap
    Input ip:port to Nmap scan

  masscan
    Input ip to syn scan

  tcpscan
    Input ip to tcp scan

  crack
    Input ip\port\service to crack

Run "flowscan <command> --help" for more information on a command.
```
```
ubuntu:~/flowscan$ sudo ./flowscan nmap -h
Usage: flowscan nmap

Input ip:port to Nmap scan

Flags:
  -h, --help                                         Show context-sensitive help.

  -t, --max-threads=50                               Max threads
  -x, --explore-timeout=5s
  -o, --option=KEY=VALUE;...
  -w, --tech-detect-file=""                          the path for wappalyzer technology
  -d, --tech-detect                                  display technology in use based on wappalyzer dataset
      --random-agent                                 enable Random User-Agent to use
  -r, --retries=0                                    HTTPX Max Retries
      --proxy=""                                     http proxy to use (eg http://127.0.0.1:8080)
      --follow-redirects                             HTTPX follow http redirects
      --follow-host-redirects                        follow redirects on the same host
      --max-redirects=10                             HTTPX max number of redirects to follow per host
  -s, --tls-grab                                     perform TLS(SSL) data grabbing
      --max-response-body-size-to-save=2147483647    HTTPX max response size to save in bytes
      --max-response-body-size-to-read=2147483647    HTTPX max response size to read in bytes
      --debug
  -b, --db-output=""                                 db(mongo) to write output results eg.dburl+dbname+collection
```
```
Usage: flowscan masscan

Input ip to Nmap scan

Flags:
  -h, --help              Show context-sensitive help.

  -t, --max-threads=50    Max threads
  -x, --timeout=10s
  -i, --host=""           host to scan
  -l, --host-file=""      host list to scan
  -p, --port=""           Port to scan
  -r, --rate=1000         syn scan rate
      --debug
```
```
ubuntu@VM-20-4-ubuntu:~/flowscan$ ./flowscan tcpscan -h
Usage: flowscan tcpscan

Input ip to tcp scan

Flags:
  -h, --help               Show context-sensitive help.

  -t, --max-threads=500    Max threads
  -x, --timeout=2s
  -i, --host=""            host to scan
  -l, --host-file=""       host list to scan
  -p, --port=""            Port to scan
      --debug
```
```
./flowscan crack -h
Usage: flowscan crack

Input ip\port\service to crack

Flags:
  -h, --help                  Show context-sensitive help.

  -t, --max-threads=20        Max threads
  -x, --explore-timeout=2s
      --debug
      --delay=0
      --crack-all
  -p, --port-info             print nmap portInfo
  -b, --db-output=""          db(mongo) to write output results eg.dburl+dbname+collection
  -j, --json-output=""        json to write output results eg.result.json
```
```
ubuntu@VM-20-4-ubuntu:~/flowscan$ ./flowscan poc -h
Usage: flowscan poc

Input url to poc scan

Flags:
  -h, --help                  Show context-sensitive help.

  -t, --max-threads=20        Max threads
  -x, --explore-timeout=2s
      --debug
  -s, --search=""             search PoC by keyword , eg: -s tomcat,phpinfo
      --finger                filter PoC by Finger
  -S, --severity=""           pocs to run based on severity. Possible values: info, low, medium, high, critical, unknown
  -u, --update-pocs           update afrog-pocs
  -l, --print-pocs            print afrog-pocs list
  -f, --pocs-file-path=""     afrog-pocs PocsFilePath
  -p, --port-info             print nmap portInfo
  -b, --db-output=""          db(mongo) to write output results eg.dburl+dbname+collection
  -j, --json-output=""        json to write output results eg.result.json
```
### 例子
top1000扫描
```
sudo ./flowscan masscan -i 192.168.10.1 | ./flowscan nmap -d
./flowscan tcpscan -i 192.168.10.1 | ./flowscan nmap -d
```
全端口扫描
```
sudo ./flowscan masscan -i 192.168.10.1 -p 1-65535| ./flowscan nmap -d
./flowscan tcpscan -i 192.168.10.1 -p 1-65535 | ./flowscan nmap -d
```

扫描常用web
```
sudo ./flowscan masscan -i 192.168.10.1 -p 80,443,4443,5000,7070,8000,8008,8080,8081,8088,8090,8123,8180,8880,8181,8443,8888,9000,9080,9090,9091,9092,9443,9200,9980,10000| ./flowscan nmap -d
```

扫描url指纹
```
echo http://www.xxxx.com | ./flowscan nmap -d
echo www.xxxx.com:8000 | ./flowscan nmap -d
echo www.xxxx.com:8000+127.0.0.1 | ./flowscan nmap -d
cat url.txt | ./flowscan nmap -d
```

扫描服务弱口令
```
sudo ./flowscan masscan -i 192.168.10.1 | ./flowscan nmap -d | ./flowscan crack

##或者
sudo ./flowscan masscan -i 192.168.10.1 | ./flowscan nmap -d -j port_result.json
cat port_result.json | ./flowscan crack
```

扫描POC
```
sudo ./flowscan masscan -i 192.168.10.1 | ./flowscan nmap -d | ./flowscan poc

##或者
sudo ./flowscan masscan -i 192.168.10.1 | ./flowscan nmap -d -j port_result.json
cat port_result.json | ./flowscan poc
```

json类型结果转csv格式
```
cat 1.json | ./flowscan csv
```