# Global Socket Root Login Shell from systemd
**Connect to a firewalled host**

**Problem**  
ALICE and BOB are on two different networks and behind a NAT/Firewall. Neither of them can reach the other.

**Objective**  
Allow BOB to log-in to ALICE as root/superuser (without tampering with the firewall, NAT or router settings).

**Solution**  
Start gs-netcat as a service (systemd) on ALICE.


On workstation "ALICE" create */etc/systemd/system/gs-root-shell.service*:
```EditorConfig
[Unit]
Description=Global Socket Root Shell
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
WorkingDirectory=/root
ExecStart=gs-netcat -k /etc/systemd/gs-root-shell-key.txt -il

[Install]
WantedBy=multi-user.target
```

Create a random key file:
```ShellSession
root@ALICE:~# gs-netcat -g >/etc/systemd/gs-root-shell-key.txt
root@ALICE:~# chmod 600 /etc/systemd/gs-root-shell-key.txt
root@ALICE:~# cat /etc/systemd/gs-root-shell-key.txt
ExampleSecretChangeMe
```

Start the service:
```ShellSession
root@ALICE:~# systemctl start gs-root-shell
```

Enable the service to start automatically after reboot:
```ShellSession
root@ALICE:~# systemctl enable gs-root-shell
```

Check that gs-netcat is running:
```ShellSession
root@ALICE:~# systemctl status gs-root-shell
```

Now log-in from "BOB" to "ALICE":
```ShellSession
b@BOB:~$ gs-netcat -s ExampleSecretChangeMe -i
=Secret         : "ExampleSecretChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
root@ALICE:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ALICE:~#
```

Et voila a root shell on ALICE.

Many more gs-netcat options are available: For example *-T* to connect via TOR or *-L* for log-output. See the manual page for gs-netcat. 
