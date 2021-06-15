#! /bin/bash


date_bin="date"
command -v gdate >/dev/null && date_bin="gdate"
unset GSOCKET_IP


MIN()
{
	echo $(($1>$2 ? $2 : $1))
}

gsrn_ping()
{
	SECRET=$(gs-netcat -g)

	export GSOCKET_HOST=$1
	export SECRET
	VARBACK=$(mktemp)

	GSPID="$(sh -c 'gs-netcat -s "$SECRET" -l -e cat &>/dev/null & echo ${!}')"
	M=31337000000

	(sleep 1; for x in $(seq 1 3); do $date_bin +%s%N; sleep 0.5; done) | gs-netcat -s "$SECRET" -w -q| while read -r x; do
		! [[ $x =~ ^16 ]] && continue

		D=$(($($date_bin +%s%N) - x))
		# printf "%s %.3fms\n" "$1" "$(echo "$D"/1000000 | bc -l)"
		M=$(MIN $M $D)
		echo "$M" >"$VARBACK"
	done
	D=$(cat "$VARBACK")
	rm -f "$VARBACK"
	printf "MIN %s %.3fms\n" "$1" "$(echo "$D"/1000000 | bc -l)"

	kill "$GSPID"
}


# gsrn_ping gs1.thc.org; exit
# gsrn_ping gs5.thc.org; exit

for n in $(seq 1 5); do
	gsrn_ping "gs${n}.thc.org"
done




