# flowscan
masscan和nmap结合体，通过pipeline串联起来,masscan需要使用root权限

## 用法
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
### 例子
top1000扫描
```
sudo ./flowscan masscan -i 192.168.10.1 | ./flowscan nmap -d
```

#扫描常用web
```
sudo ./flowscan masscan -i 192.168.10.1 -p 80,443,4443,5000,7070,8000,8008,8080,8081,8088,8090,8123,8180,8880,8181,8443,8888,9000,9080,9090,9091,9092,9443,9200,9980,10000| ./flowscan nmap -d
```