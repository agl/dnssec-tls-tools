#! /bin/bash

# Configuration settings
PRIVKEY=/etc/ssl/certs/dnssec/privkey.pem
CERTDIR=/etc/ssl/certs
WEBSERVER=apache2

# Use the directory we are running in to find other commands
MYDIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
GENCERT=$MYDIR/gencert
if [ ! -x $GENCERT ]; then
   echo "Please compile gencert.c into $GENCERT"
   echo "gcc -o gencert gencert.c -Wall -lcrypto"
   exit 1
fi

HOST=$1
if [ x$HOST = x ]; then
   echo "Please give a host."
   exit 1
fi

HOST_FILTERED=$(echo $HOST | sed -e's/\./_/g').pem
HOST_CERT=$CERTDIR/$HOST_FILTERED

# Set umask, so new files can't be read by anyone apart from root
umask u=rwx,g=r,o=

# Create the temporary files
TMP_HOST_CERT=""
TMP_CHAIN=""
function cleanup() {
    if [ -e "$TMP_HOST_CERT" ]; then
       rm $TMP_HOST_CERT
    fi
    if [ -e "$TMP_CHAIN" ]; then
       rm $TMP_CHAIN
    fi
}
trap cleanup SIGINT
trap cleanup EXIT

TMP_HOST_CERT=$(mktemp $HOST_FILTERED.pem.XXXXXX)
TMP_CHAIN=$(mktemp $HOST_FILTERED.chain.XXXXXX)

# Get the chain
python chain.py $HOST $TMP_CHAIN
CHAIN_SUCCESS=$?

# Generate the certificate
$GENCERT $PRIVKEY $TMP_CHAIN > $TMP_HOST_CERT
GENCERT_SUCCESS=$?

if [ $CHAIN_SUCCESS -eq 0 -a $GENCERT_SUCCESS -eq 0 ]; then
    mv $TMP_HOST_CERT $HOST_CERT
    # HUP the server
    /etc/init.d/$WEBSERVER reload
else
    echo "An error occured when updating the dnssec cert."
    echo "python chain.py returned $CHAIN_SUCCESS"
    echo "gencert returned $GENCERT_SUCCESS"
    echo "See previous output for errors."
    exit 100
fi
