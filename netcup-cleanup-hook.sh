#!/bin/bash

#absolute path of this script
ABSPATH=$( dirname $(readlink -f $0))

$ABSPATH/netcup-dns-hook.py remove -domain $CERTBOT_DOMAIN -host _acme-challenge -type TXT
