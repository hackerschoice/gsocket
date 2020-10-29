#! /bin/sh

command -v git >/dev/null 2>&1 || { echo >&2 "git not found. Try 'apt-get install git'"; exit 1; }
git clone --depth 1 https://github.com/hackerschoice/gsocket.git
cd gsocket
./bootstrap
./configure && make && echo "Type 'cd gsocket; sudo make install' to install."

