

GSOCKET works on Linux, FreeBSD, MacOS, Cygwin and many others. If the particular OS is not listed here then try the *Install Script* or *compile from source*.

---
**Generic - Install Script**
```
/bin/bash -c "$(curl -fsSL https://tiny.cc/gsinst)"
```
---
**Generic - Compile from Source**

Download the [latest source](https://github.com/hackerschoice/gsocket/releases/tag/v1.4.33).
```
tar xfz gsocket-*.tar.gz
cd gsocket-*
./configure && make install
```
---
**Debian sid**
```
apt update
apt install gsocket
```
---
**Ubuntu**
```
curl -fsSL https://github.com/hackerschoice/binary/raw/main/gsocket/latest/gsocket_1.4.32_all.deb --output gsocket_latest.deb
dpkg -i gsocket_latest.deb
```
---
**FreeBSD**
```
pkg update
pkg install gsocket
```
---
**Docker**

Try gsocket right now with docker.
```
docker run --rm -it hackerschoice/gsocket
```
```
docker run --rm -it hackerschoice/gsocket-tor
```
---







