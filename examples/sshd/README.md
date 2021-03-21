# OpenSSH via Global Socket
**Connect with ssh to a firewalled host**

**Problem**  
ALICE and BOB are on two different networks and behind a NAT/Firewall. Neither of them can reach the other.

**Objective**  
Allow user bob on host BOB to log-in with ssh as user bob on host ALICE (without tampering with the firewall, NAT or router settings).

**Solution**  
Start sshd and ssh with the *gs* tool to (automatically) redirect any ssh-traffic via the Global Socket Relay Network.


Let's test the *gs* concept. Start *sshd* on ALICE via the *gs* tool. The *-D* parameter is used for keeping sshd in the foreground (for testing):
```ShellSession
root@ALICE:~# gs -s ExampleSecretChangeMe /usr/sbin/sshd -D
```

Any networking application can be made accessible via the Global Socket Relay Network (GSRN): The *gs* tool hooks all network functions and instead redirects those via the GSRN. In the above example the *gs* tool hooks the 'listen()' call and listens on a Global Socket named *ExampleSecretChangeMe* instead. Anyone with the correct secret (*ExampleSecretChangeMe*) is now able to connect to this sshd from anywhere in the world. The sshd process will _not_ listen on the default SSHD port 22 but on the Global Socket named *ExampleSecretChangeMe* instead. (On Global Socket we use names instead of numbers).

From BOB use the *gs* tool to log in to ALICE:
```ShellSession
bob@BOB:~$ gs -s ExampleSecretChangeMe ssh bob@gsocket
```

Any networking application that connects to a hostname ending with *gsocket* (or *blah.anything.gsocket*) is redirected via the GSRN. 

**Installation**

Let's make this change permanent so that ALICE is accessible via the GSRN after a system reboot. This does not tamper with the default *SSHD* service in any way. It is an additional service which will run alongside the default *SSHD* service.

Copy the default sshd.service:
```ShellSession
root@ALICE:~# cd /etc/systemd/system
root@ALICE:/etc/systemd/system# cp sshd.service gs-sshd.service
root@ALICE:/etc/systemd/system# chmod 600 gs-sshd.service
```

Edit the *gs-sshd.service* file and change this line:
```EditorConfig
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
```
to
```EditorConfig
ExecStart=gs -s ExampleSecretChangeMe /usr/sbin/sshd -D $SSHD_OPTS
```

Start, check and enable the newly created service:
```ShellSession
root@ALICE:~# systemctl start gs-sshd
root@ALICE:~# systemctl status gs-sshd
root@ALICE:~# systemctl enable gs-sshd
```

Log in to host ALICE from anywhere in the world:
```ShellSession
bob@BOB:~$ gs ssh bob@gsocket
Enter Secret (or press Enter to generate): ExampleSecretChangeMe
=Secret         :"ExampleSecretChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-65-generic x86_64)
bob@ALICE:~$ 
```

**Notes**
Do not use *ExampleSecretChangeMe*. Generate your own secret using the *-g* option:
```ShellSession
$ gs -g
M9BfcYhhG4LujcPTbUcaZN
```

This example uses double encryption: The GSRN connection is encrypted with OpenSSL's SRP protocol and within that tunnel OpenSSH uses its own encryption. This also means that the SSHD on the GSRN is only accessible to those who know the secret (*ExampleSecretChangeMe*). E.g. the listening TCP port is hidden. The *-C* option can be used to disable GSRN encryption and rely on OpenSSH's encryption only.

Many more gs options are available: For example *-T* to connect via TOR. See the manual page for gs. 
