# dhcp-server
*This project is not finished, and not everything works as it should.*

Simple DHCPv4 server written in C++.
All setting are stored in one configuration file with pairs `param=value`.
Values at top are global, after `range` directive are applied to range of addresses and after `host` - they are settings for single host (reservation)

config.txt
```
# global: 
interface=enp0s3
routers=255.255.255.255
mask=255.255.255.0
time=3600s
routers=192.168.1.254,16.16.16.16
domain=www.domena.local
dns=1.1.1.1

# ranges:
range=192.168.1.100-192.168.1.145
mask=/24
dns=8.8.8.8,8.8.4.4
routers=192.168.1.254

range=192.168.1.170-192.168.1.200
dns=1.1.1.1

# reservation:
host=080027B935CC
ip=192.168.1.150
time=8h
```

If any settings are missing, then global values are applied.
