# Global Socket WireGuard Example
**Connect two firewalled hosts with wireGuard (Virtual Private Network)**

**Problem**  
ALICE and BOB are on two different networks behind NAT/Firewall. Neither of them can reach the other. A WireGuard VPN can not be established (ALICE and BOB are both firewalled).

**Objective**  
Create a WireGuard Virtual Private Network between ALICE and BOB (without tampering with the firewall, NAT or router settings).

**Solution**  
Redirect the WireGuard traffic via the Global Socket Relay Network.

ALICE -> WireGuard -> Global Socket Relay Network -> WireGuard -> BOB

On workstation "ALICE":
```ShellSession
a@ALICE:~ $ wg-quick up ./wg0-server.conf
```

On workstation "BOB":
```ShellSession
b@BOB:~ $ wg-quick up ./wg0-client.conf
```

Test the WireGuard VPN:
```ShellSession
b@BOB:~ $ ping 10.37.0.1
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
PreUp = gs-netcat -s ExampleSecretChangeMe -Culq -d 127.0.0.1 -p 51820 &
PostDOwn = killall -g gs-netcat

[Peer]
# Client #1
PublicKey = KRYz7Jsbu1pS6ALHLqCUqG4KsFh9GcK3II+3bFscYUU=
AllowedIPs = 10.37.0.2/32
```

This is a default WireGuard configuration file for a server. The only change is:
```Nginx
PreUp = gs-netcat -s ExampleSecretChangeMe -Culq -d 127.0.0.1 -p 51820 &
```
This starts a gs-netcat process and redirects any traffic from the Global Socket *ExampleSecretChangeMe* to the default WireGuard port (51820). *-u* specifies UDP protocol and *-q* to be quiet.


Let's take a look at wg-client.conf (BOB):
```Nginx
[Interface]
# client. ME
Address = 10.37.0.2/32
PrivateKey = SOnUcf+KuXIWXfhpZpHtTC097ihBNUXT2igp5IuJsWY=
# Make gs-netcat listen on UDP 31337
PreUp = gs-netcat -s ExampleSecretChangeMe -Cuq -p 31337 &
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
PreUp = gs-netcat -s ExampleSecretChangeMe -Cuq -p 31337 &
[...]
EndPoint = 127.0.0.1:31337
```
The PreUp-line redirects any UDP traffic from port 31337 to the Global Socket *ExampleSecretChangeMe*. The new *Endpoint* instructs WireGuard to send all WireGuard traffic to the UDP port where gs-netcat is listening (31337). Any UDP traffic received by gs-netcat is forwarded (via the Global Socket Relay Network) to the other gs-netcat running on ALICE.

**Notes**  
The gs-netcat secret *ExampleSecretChangeMe* is chosen at random but has to be identical on ALICE and BOB. This string is used by the Global Socket Relay Network to connect ALICE and BOB. Use *gs-netcat -g* to generate a new random string for your own use (do not use the example).

Create your own private/public WireGuard keys (do not use the example):
```ShellSession
$ wg genkey | tee server-privatekey | wg pubkey > server-publickey
$ wg genkey | tee client-privatekey | wg pubkey > client-publickey

```

Many more gs-netcat options are available: For example *-T* to connect WireGuard via TOR or *-L* for log-output. See the manual page for gs-netcat. 

