#! /bin/bash

MYDIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

HOST=$1
HOST_CERT=/etc/ssl/certs/$(echo $HOST | sed -e's/\./_/g').pem
PRIVKEY=/etc/ssl/certs/dnssec/privkey.pem
WEBSERVER=apache2
CHAIN=/tmp/$HOST.chain
GENCERT=$MYDIR/gencert

if [ x$HOST = x ]; then
   echo "Please give a host."
   exit 1
fi

if [ ! -x $GENCERT ]; then
   echo "Please compile gencert.c into $GENCERT"
   echo "gcc -o gencert gencert.c -Wall -lcrypto"
   exit 1
fi

umask u=rwx,g=r,o=

# Get the chain
python chain.py $HOST $CHAIN
# Generate the certificate
$GENCERT $PRIVKEY $CHAIN > $HOST_CERT

# Remove the chain
rm $CHAIN

# HUP the server
/etc/init.d/$WEBSERVER reload
