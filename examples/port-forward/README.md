# Global Socket Port Forwarding
**Connect to a firewalled host**

**Problem**  
A hypothetical example for BOB to connect to ALICE's IRCD. Both are on two different networks and behind a NAT/Firewall. Neither of them can reach the other.

**Objective**  
Allow BOB to access ALICE's (private) IRCD service (without tampering with the firewall, NAT or router settings).

**Solution**  
Create a port forward to ALICE's IRCD and make this forward accessible via the Global Socket Relay network (GSRN).

**Prerequisite**
IRCD running on ALICE's workstation and an IRC client (irssi) on BOB's workstation.

On workstation "ALICE" create */etc/system/systemd/gs-portforward.service* to configure a port forward from the Global Socket *ExampleSecretChangeMe* to TCP port 6667 on your workstation (127.0.0.1):
```EditorConfig
[Unit]
Description=Global Socket IRCD Forward
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStart=gs-netcat -s ExampleSecretChangeMe -l -d 127.0.0.1 -p 6667

[Install]
WantedBy=multi-user.target
```

Start, check and enable the service:
```ShellSession
root@ALICE:~# systemctl start gs-portforward
root@ALICE:~# systemctl status gs-portforward
root@ALICE:~# systemctl enable gs-portforward
```

On BOB's workstation create a port forward from TCP port 6667 to the Global Socket *ExampleSecretChangeMe*:
```ShellSession
b@BOB:~$ gs-netcat -s ExampleSecretChangeMe -p 6667
```

TCP port 6667 on BOB's workstation is now forwarded to TCP port 6667 on ALICE's workstation. Bob connects to ALICE's IRCD as if the IRCD is running on his workstation (127.0.0.1):
```ShellSession
b@BOB:~$ irssi -c 127.0.0.1
```

Alternatively of using two separate commands BOB can use the *gsocket* tool to start the irc client and automatically forward the connection via the GSRN:
```ShellSession
b@BOB:~$ gsocket irssi -c blah.gsocket
Enter Secret (or press Enter to generate): ExampleSecretChangeMe
=Secret         :"ExampleSecretChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
Irssi v1.2.0-2 - https://irssi.org
06:22 -!- Irssi: Looking up blahgsocket
06:22 -!- Irssi: Connecting to blah.gsocket [127.31.33.7] port 6667
[...]
```

This is a hypothetical example. Alice can configure the port forward by changing 127.0.0.1 to the desired destination.

Alice created a port forward and started the IRCD service. Instead Alice can combine this into a single command:

```ShellSession
alice@ALICE:~$ gsocket inspircd --nolog --nofork 
Enter Secret (or press Enter to generate): ExampleSecretChangeMe
=Secret         :"ExampleSecretChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
Inspire Internet Relay Chat Server
(C) InspIRCd Development Team.
[...]
```

Many more gs-netcat options are available: For example *-T* to connect via TOR or *-L* for log-output. See the manual page for gs-netcat. 
