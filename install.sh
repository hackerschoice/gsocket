#! /bin/sh

git clone https://github.com/hackerschoice/gsocket.git
cd gsocket
./bootstrap
./configure && make

