#! /bin/bash

printf 'const char *man_str = \"\\\n'

man ./gs-netcat.1 2>/dev/null | col -b | sed 's/"/\\"/g' | perl -p -e 's/\n/\\n\\\n/'

printf '\";\n'

