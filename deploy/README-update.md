

All gs-netcat installations need to be updated to at least 1.4.32.

How to update a deployed gs-netcat from https://www.gsocket.io/deploy to the latest gs-netcat version.
---
1. Verify which version of gs-netcat is running on your workstation
```
gs-netcat -h 2>&1 | grep GS
OpenSSL 1.1.1k  25 Mar 2021 [0x101010bfL] (GS v1.4.30)
```

2. Update gs-netcat on your workstation to 1.4.32 or later:
```
cp $(command -v gs-netcat) $(command -v gs-netcat)-old
/bin/bash -c "$(curl -fsSL https://tiny.cc/gsinst)"
```

3. 1. Log in to your depoyed gs-netcat shell using the old version of gs-netcat (<1.4.32):
```
gs-netcat-old -i
```

3. 2. Alternativly use one of these commands to access your old sessions:
```
S=YourSecret bash -c "$(curl -fsSL gsocket.io/xold)"
S=YourSecret bash -c "$(wget -qO- gsocket.io/xold)"
```

4. On the remote shell execute these commands (replace *YourSecret* with your secret):
```
GS_UNDO=1 bash -c "$(curl -fsSL gsocket.io/xold)"
GSPID=$(pidof gs-bd)
X=YourSecret bash -c "$(curl -fsSL gsocket.io/x)"
kill $GSPID
```

5. Log in to your newly deployed gs-netcat (using verion 1.4.32 or later):
```
gs-netcat -i
```

---

Pro Tip: Upgrade your local gs-netcat with the static binary:
```
GS_UPDATE=1 bash -c "$(curl -fsSL gsocket.io/x)"
```
or
```
GS_UPDATE=1 bash -c "$(wget -qO- gsocket.io/x)"
```


