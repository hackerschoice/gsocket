# OpenSSH via Global Socket
**Connect with ssh to a firewalled host**

**Problem**  
ALICE and BOB are on two different networks and behind a NAT/Firewall. Neither of them can reach the other.

**Objective**  
Allow user bob on host BOB to log-in with ssh as user bob on host ALICE (without tampering with the firewall, NAT or router settings).

**Solution**  
Start sshd and ssh with the *gsocket* tool to (automatically) redirect any ssh-traffic via the Global Socket Relay Network.


Let's test the *gsocket* concept. Start *sshd* on ALICE with the *gsocket* tool:
```ShellSession
root@ALICE:~# gsocket -s ExampleSecretChangeMe /usr/sbin/sshd -D
```

The *gsocket* tool hooks all network functions and instead redirects those via the GSRN. The above example redirects the 'listen()'-call and listens on the Global Socket named *ExampleSecretChangeMe* instead of sshd's port 22.

Anyone with the correct secret (*ExampleSecretChangeMe*) can now connect to this sshd from anywhere in the world. The sshd process will _not_ listen on the default SSHD port 22 but instead on a Global Socket named *ExampleSecretChangeMe*. (On Global Socket we use names and not numbers).

From BOB use the *gsocket* tool to log in to ALICE:
```ShellSession
bob@BOB:~$ gsocket ssh bob@gsocket
Enter Secret (or press Enter to generate): ExampleSecretChangeMe
=Secret         :"ExampleSecretChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-65-generic x86_64)
bob@ALICE:~$ 
```

Any networking application that connects to a hostname ending in *gsocket* (or *blah.anything.gsocket*) is redirected via the GSRN. 

**Installation**

Let's make this change permanent so that ALICE is accessible via the GSRN after a system reboot. This does not tamper with the default *SSHD* service in any way. The *GS-SSHD* runs as an additional service alongside the default *SSHD* service.

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
bob@BOB:~$ gsocket ssh bob@gsocket
Enter Secret (or press Enter to generate): ExampleSecretChangeMe
=Secret         :"ExampleSecretChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-65-generic x86_64)
bob@ALICE:~$ 
```

**Advanced Tips**

Under the hood ```gsocket``` forks a gs-netcat process with a new SECRET of *&lt;PORTNUMBER>-&lt;SECRET>*. Continuing from the example, and instead of using ```gsocket /usr/sbin/sshd -D``` it is possible to use a port forward to the original *sshd* on port 22 instead:

```ShellSession
root@ALICE:~# gs-netcat -s 22-ExampleSecretChangeMe -l -d 127.1 -p 22
```
and then use *ssh* the same way as previously:
```ShellSession
bob@BOB:~$ gsocket ssh bob@gsocket
```
or, and instead of using ```gsocket ssh bob@gsocket``` it is possible to use gs-netcat to test the connection to the *sshd*:
```ShellSession
bob@BOB:~$ gs-netcat -s 22-ExampleSecretChangeMe
SSH-2.0-OpenSSH_8.6
```


**Notes**

Do not use *ExampleSecretChangeMe*. Generate your own secret using the *-g* option:
```ShellSession
$ gsocket -g
M9BfcYhhG4LujcPTbUcaZN
```

This example uses double encryption: The GSRN connection is encrypted with OpenSSL's SRP protocol and within that tunnel OpenSSH uses its own encryption. As a consequence the GS-SSHD is only accessible to those who know the secret (*ExampleSecretChangeMe*). E.g. the TCP port and service is hidden. The *-C* option can be used to disable GSRN encryption and rely on OpenSSH's encryption only.

Changing the hostname from *gsocket* to *thc* will connect through TOR first: ssh -> TOR -> GSRN....

Many more gs options are available. See the manual page for gs. 
