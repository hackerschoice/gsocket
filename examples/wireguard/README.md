# Global Socket Wireguard Example
**Connect two firewalled hosts with wireguard (Virtual Private Network)**

**Problem**  
ALICE and BOB are on two different networks behind NAT/Firewall. Neither of them can reach the other. A wireguard VPN can not be established (ALICE and BOB are both firerwalled).

**Objective**  
Create a wireguard Virtual Private Network between ALICE and BOB (without tampering with the firewall, NAT or router settings).

**Solution**  
Redirect the wireguard taffic via the the Global Socket Relay Network.

ALICE -> wireguard -> Global Socket Relay Network -> wireguard -> BOB

On workstation "ALICE":
```shell
ALICE :~ $ wg-quick up ./wg0-server.conf
```

On workstation "BOB":
```shell
BOB :~ $ wg-quick up ./wg0-client.conf
```

Test the wireguard VPN:
```shell
BOB :~ $ ping 10.37.0.1
PING 10.37.0.1 (10.37.0.1) 56(84) bytes of data.
64 bytes from 10.37.0.1: icmp_seq=1 ttl=64 time=46.96 ms
[...]
```

**Explanation**

Let's take a look at wg-server.conf (ALICE)
```Nginx
[Interface]
# Server
Address = 10.37.0.1/24
ListenPort = 51820
PrivateKey = 4E48vR7v8OUJO5OEYkOUUZmF55UOYVqo9l9w2eRS50k=
PostUp = sysctl -w net.ipv4.ip_forward=1
PreUp = gs-netcat -s AnyKindOfRandomString -CuDl -d 127.0.0.1 -p 51820
PostDOwn = killall -g gs-netcat

[Peer]
# Client #1
PublicKey = KRYz7Jsbu1pS6ALHLqCUqG4KsFh9GcK3II+3bFscYUU=
AllowedIPs = 10.37.0.2/32
```

This is a default wireguard configuration file for the server side. The only change is:
```Nginx
PreUp = gs-netcat -s AnyKindOfRandomString -CuDl -d 127.0.0.1 -p 51820
```
This starts a gs-netcat process and redirects any traffic from Global Socket *AnyKindOfRandomString* to the default wireguard port (51820). *-u* specifies UDP protocol. *-D* starts gs-netcat as a background process.


Let's take a look at wg-client.conf (BOB):
```Nginx
[Interface]
# client. ME
Address = 10.37.0.2/32
PrivateKey = SOnUcf+KuXIWXfhpZpHtTC097ihBNUXT2igp5IuJsWY=
# Make gs-netcat listen on UDP 31337
PreUp = gs-netcat -s AnyKindOfRandomString -CuD -p 31337
PostDown = killall -g gs-netcat

[Peer]
# server
Endpoint = 127.0.0.1:31337
PublicKey = gjBE/V1pGdIu7yTGWtZvObxIf9+ErH9aRP+jsBuiXC4=
AllowedIPs = 10.37.0.0/24
PersistentKeepalive = 25
```

The only change is:
```Nginx
PreUp = gs-netcat -s AnyKindOfRandomString -CuD -p 31337
[...]
EndPoint = 127.0.0.1:31337
```
The PreUp-line starts gs-netat. This will redirect any UDP traffic from port 31337 to the Global Socket *AnyKindOfRandomString*. The new *Endpoint* instructs wireguard to send all wireguard traffic to UDP port where gs-netcat is listening.


See the manual page of gs-netcat for all the options. This is an example.



