

All gs-netcat installations need to be updated to at least 1.4.32.

How to update a deployed gs-netcat from https://www.gsocket.io/deploy to the latest gs-netcat version.

1. Update gs-netcat on your workstation to 1.4.32 or later:
```
cp $(command -v gs-netcat) $(command -v gs-netcat)-old
/bin/bash -c "$(curl -fsSL https://tiny.cc/gsinst)"
```

2. Log in to your depoyed gs-netcat shell using the old version of gs-netcat (<1.4.32):
```
gs-netcat-old -i
```

3. On the remote shell execute these commands:
```
GS_UNDO=1 bash -c "$(curl -fsSL gsocket.io/x)"
GSPID=$(pidof gs-bd)
X=YourOldSecret bash -c "$(curl -fsSL gsocket.io/x)"  # Optionally prefix with X=YourOldSecret
kill $GSPID
```

4. Log in to your newly deployed gs-netcat uisng a newer gs-netcat (1.4.32 or later):
```
gs-netcat -i
```


