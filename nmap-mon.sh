#!/bin/bash
#nmap-mon.sh
#Bash script to email admin when changes are detected in a network using
Nmap and Ndiff.
#Don't forget to adjust the CONFIGURATION variables.
#Paulino Calderon <calderon@websec.mx>

#
#CONFIGURATION
#
NETWORK="YOURDOMAIN.COM"
ADMIN=YOUR@EMAIL.COM
NMAP_FLAGS="-sV -Pn -p- -T4"
BASE_PATH=/usr/local/share/nmap-mon/
BIN_PATH=/usr/local/bin/
BASE_FILE=base.xml
NDIFF_FILE=ndiff.log
NEW_RESULTS_FILE=newscanresults.xml
BASE_RESULTS="$BASE_PATH$BASE_FILE"
NEW_RESULTS="$BASE_PATH$NEW_RESULTS_FILE"
NDIFF_RESULTS="$BASE_PATH$NDIFF_FILE"

if [ -f $BASE_RESULTS ]
then
  echo "Checking host $NETWORK"
  ${BIN_PATH}nmap -oX $NEW_RESULTS $NMAP_FLAGS $NETWORK
  ${BIN_PATH}ndiff $BASE_RESULTS $NEW_RESULTS > $NDIFF_RESULTS
  if [ $(cat $NDIFF_RESULTS | wc -l) -gt 0 ]
  then
    echo "Network changes detected in $NETWORK"
    cat $NDIFF_RESULTS
    echo "Alerting admin $ADMIN"
    mail -s "Network changes detected in $NETWORK" $ADMIN < $NDIFF_RESULTS
  fi 
fi
