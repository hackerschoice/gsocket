# Global Socket
**Moving data from here to there. Securely, Fast and trough NAT/Firewalls.**

Global Socket enables two users behind NAT/Firewall to establish a TCP connection with each other. Securely.

**Features:**
- Uses the Global Socket Relay Network to connect TCP pipes
- End-2-End encryption using (OpenSSL's SRP / RFC 5054)
- AES-256 with a 4096 Prime
- TOR support (optional)


BETA BETA BETA. PRIVATE RELEASE ONLY.

**Installation:**
```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/hackerschoice/gsocket/master/install.sh)"
```

**Usage:**

1. Log in to *Host* from *Workstation* through any firewall/NAT
```
$ ./gs-netcat -i -l   # Host
$ ./gs-netcat -i      # Workstation
```

2. Transfer files from *Workstation* to *Host*
```
$ ./gs-netcat -rl >warez.tar.gz    # Host
$ ./gs-netcat -w <warez.tar.gz     # Workstation
```

3. Port forward. *Workstation's* Port 2222 is forwarded to 192.168.6.7 on *Host's* private LAN
```
$ ./gs-netcat -l -d 192.168.6.7 -p 22 # Host
$ ./gs-netcat -p 2222                 # Workstation
$ ssh -p 2222 root@127.0.0.1          # Will ssh to 192.168.6.7 on Host's private LAN

```
4. Execute any command (nc -e style)
```
$ ./gs-netcat -l -e "echo hello world; id; exit"   # Host
$ ./gs-netcat                                      # Workstation
```

5. Quick Secure Chat with a friend:
```
$ ./gs-full-pipe -s MySecret -A               # You
$ ./gs-full-pipe -s MySecret -A               # Him
```

*Pro-Tips:*

1. Force Tor or fail:
```
$ export GSOCKET_SOCKS_IP=127.0.0.1
```

2. A reverse backdoor

The backdoor supports multiple concurrent connections and spawns a real PTY/interactive-shell with ctrl-c and colors working (like OpenSSH does).
```
$ ./gs-netcat -k keyfile.txt -il      # Host
$ ./gs-netcat -k keyfile.txt -T -i    # Workstation (via Tor & Global Socket Relay)
```

3. Use -k

Using -s is not secure. Add your *secret* to a file and use -k or pipe your password into the programme:
(Note the 3x '<').
```
$ ./gs-netcat -li <<<"MySecretPassword"
```


Join us Telegram: https://t.me/thcorg

shoutz: D1G, xaitax, #!adm
