#! /bin/bash

for x in *.1; do
	man2html -H hackerschoice.github.io  -M'/' -p <"${x}" | sed -e 's/\(\:\/\/hackerschoice\.github\.io\/\)\/\([0-9]\)+\([a-z-]*\)/s\1\3.\2.html/g' >"${x}.html"

done

