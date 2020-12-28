#!/bin/bash

#absolute path of this script
ABSPATH=$( dirname $(readlink -f $0))

$ABSPATH/netcup-dns-hook.py $CERTBOT_DOMAIN $CERTBOT_VALIDATION --cleanup
