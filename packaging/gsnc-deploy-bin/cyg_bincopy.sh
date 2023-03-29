#! /bin/bash

prgcp()
{
    local bin
    local arr
    bin=$1

    [[ ! -e "$bin" ]] && bin=$(which "$1")

    arr=($(ldd "$bin" | grep -F /usr/bin/ | awk '{print $1;}'))

    for fn in "${arr[@]}"; do
        [[ ! -f "/usr/bin/${fn}" ]] && { echo >&2 "Not found: /usr/bin/${fn}"; continue; }
        [[ -f "${dst}/${fn}" ]] && continue
        echo "fn=$fn"
        cp "/usr/bin/${fn}" "$dst"
    done

    name="${bin##*/}"
    [[ -z $name ]] && name="$bin"
    [[ -e "${dst}/${name}" ]] && return
    
    echo "cp ${bin}  => ${dst}"
    cp "${bin}" "${dst}"
}

dst="$1"
{ [[ -z ${dst} ]] || [[ ! -d "${dst}" ]] } && { echo >&2 "Destination '${dst}' not found"; exit 250; }

for n in    awk bzip2 bash cat cp curl date dd df diff du file find git gpg grep gs-netcat gunzip gzip head \
            hostname id jq kill killall ldd less ln ls md5sum mkdir more mv nc nice openssl perl ping ps \
            pwd python reset resize rm rsync sha256sum sha512sum screen scp sed sh shred ssh \
            stty socat tail tar tmux uname unzip vi vim wc wget which whereis xargs zip; do
    prgcp "$n" "$dst"
done