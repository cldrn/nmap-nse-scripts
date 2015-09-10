#!/bin/sh
#count_targets.sh <target list>
#Simple bash script to count targets from list in CIDR notation.
total=0
while IFS='' read -r line || [[ -n "$line" ]]; do
	TARGETS="$(ipcalc $line | awk {'print $2'} | sed '9q;d')"
        echo "El rango $line tiene $TARGETS objetivos"
        total=`expr $TARGETS + $total`
done < "$1"
echo "\nEl total de objetivos es $total"
