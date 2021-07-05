

All gs-netcat installations need to be updated to at least 1.4.32.

How to update a deployed gs-netcat from https://www.gsocket.io/deploy to the latest gs-netcat version.
---
1. Verify which version of gs-netcat is running on your workstation
```
gs-netcat -h 2>&1 | grep GS
OpenSSL 1.1.1k  25 Mar 2021 [0x101010bfL] (GS v1.4.30)
```

2. Use any of these commands to log into your old session:
```
gs-netcat -i
S=YourSecret bash -c "$(curl -fsSL gsocket.io/xold)"
S=YourSecret bash -c "$(wget -qO- gsocket.io/xold)"
```

3. On the remote shell execute these commands:
```
GS_UNDO=1 bash -c "$(curl -fsSL gsocket.io/xold)"
GSPID=$(pidof gs-bd)
X=YourSecret bash -c "$(curl -fsSL gsocket.io/x)"
kill $GSPID
```

4. Update gs-netcat on your workstation to 1.4.32 or later (alternatively see Pro-Tip below):
```
/bin/bash -c "$(curl -fsSL https://tiny.cc/gsinst)"
```

5. Log in to your newly deployed gs-netcat (using verion 1.4.32 or later) with any of these commands:
```
gs-netcat -i
S=YourSecret bash -c "$(curl -fsSL gsocket.io/x)"
S=YourSecret bash -c "$(wget -qO- gsocket.io/x)"
```

---

Pro-Tip: Upgrade your local gs-netcat with the static binary with any of these commands:
```
GS_UPDATE=1 bash -c "$(curl -fsSL gsocket.io/x)"
GS_UPDATE=1 bash -c "$(wget -qO- gsocket.io/x)"
```


