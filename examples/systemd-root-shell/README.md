# Global Socket Root Login Shell from systemd
**Connect to a firewalled host**

**Problem**  
ALICE and BOB are on two different networks behind NAT/Firewall. Neither of them can reach the other.

**Objective**  
Allow BOB to login to ALICE as root/superuser (without tampering with the firewall, NAT or router settings).

**Solution**  
Start gs-netcat as a service (systemd) on ALICE.


On workstation "ALICE" create */etc/system/systemd/gs-root-shell.service*:
```EditorConfig
[Unit]
Description=Global Socket Root Shell
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
WorkingDirectory=/root
ExecStart=gs-netcat -k /etc/systemd/id_sec.txt -il

[Install]
WantedBy=multi-user.target
```

Create a random key file:
```Shell
ALICE :~ $ gs-netcat -g >/etc/systemd/gs-root-shell-key.txt
ALICE :~ $ chmod 600 /etc/systemd/gs-root-shell-key.txt
ALICE :~ $ cat /etc/systemd/gs-root-shell-key.txt
ExampleKeyXXXXChangeMe
```

Start the service:
```Shell
ALICE :~ $ systemctl start gs-root-shell
```

Enable the service to start automatically after reboot:
```Shell
ALICE :~ $ systemctl enable gs-root-shell
```

Check that gs-netcat is running:
```Shell
ALICE :~ $ systemctl status gs-root-shell
```

Now login from "BOB" to "ALICE":
```ShellSession
b@BOB :~ $ gs-netcat -s ExampleKeyXXXXChangeMe -i
=Secret         : "ExampleKeyXXXXChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
root@ALICE:~# id
```

Et voila a root shell on ALICE.

Many more gs-netcat options are available: For example *-T* to connect via TOR or *-L* for log-output. See the manual page for gs-netcat. 