#!/bin/sh -e


. /usr/share/debconf/confmodule

db_version 2.0
#db_capb backup
db_capb escape
#db_settitle demo/title


# This implements a simple state machine so the back button can be handled.
STATE=1
while [ "$STATE" != 0 -a "$STATE" != 9 ]; do
        case $STATE in
        1)
                db_input medium ecca-sample-site/servername || true
        ;;
	2)
                db_input medium ecca-ca/countrycode || true
        ;;
        3)
                db_input medium ecca-ca/state-or-province || true
        ;;
        4)
                db_input medium ecca-ca/locality || true
        ;;
        5)
                db_input medium ecca-ca/organization || true
        ;;
	6)
		db_input medium ecca-ca/organizational-unit || true
        ;;
	7)
		db_input medium ecca-ca/email-address || true
	;;
	8)
		db_input medium ecca-signer/servername || true
        esac
        
        if db_go; then
                STATE=$(($STATE + 1))
        else
                STATE=$(($STATE - 1))
        fi
#       echo "ON STATE: $STATE"
done

db_stop