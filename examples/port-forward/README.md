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

On workstation "ALICE" create */etc/system/systemd/gs-portforward.service*. Configure a port forward from the Global Socket *ExampleSecretChangeMe* to port 6667:
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

On BOB's workstation create a port forward from 6667 to the Global Socket *ExampleSecretChangeMe*:
```ShellSession
b@BOB:~$ gs-netcat -s ExampleSecretChangeMe -p 6667
```

TCP port 6667 on BOB's workstation is now forwarded to TCP port 6667 on ALICE's workstation. Bob connects to ALICE's IRCD as if it would be running on his workstation (127.0.0.1):
```ShellSession
b@BOB:~$ irssi -c 127.0.0.1
```

Alternatively BOB can use the *gs* tool to start the irc client to automatically forward the connection via the GSRN:
```ShellSession
b@BOB:~$ gs irssi -c gsocket
Enter Secret (or press Enter to generate): ExampleSecretChangeMe
=Secret         :"ExampleSecretChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
```

This is a hypothetical example. Alice can configure the port forward to any other destination by changing 127.0.0.1.

Alice created a port forward and started the IRCD service. Instead Alice can combine this into a single command:

```ShellSession
alice@ALICE:~$ gs inspircd --nolog --nofork 
Enter Secret (or press Enter to generate): ExampleSecretChangeMe
=Secret         :"ExampleSecretChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
Inspire Internet Relay Chat Server
(C) InspIRCd Development Team.
[...]
```

Many more gs-netcat options are available: For example *-T* to connect via TOR or *-L* for log-output. See the manual page for gs-netcat. 
