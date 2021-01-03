#!/bin/bash

#absolute path of this script
ABSPATH=$( dirname $(readlink -f $0))

$ABSPATH/netcup-dns-hook.py add -domain $CERTBOT_DOMAIN -host _acme-challenge -destination $CERTBOT_VALIDATION -type TXT 

sleep 600 
