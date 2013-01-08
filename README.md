Here in can be found the beginnings of some tools for producing DANE stapled-certificates.

**Warning: this is mostly of historical interest as Chrome support has been removed.**

gentlsa.py:
Outputs an example TLSA record for a given public key.

chain.py:
Generates a DNSSEC chain. For example:
% python chain.py www.dnssec-exp.org chain

gencert.c:
Builds a self-signed certificate with an embedded chain. For example:
% ./gencert key.pem chain


Example
-------

    $ openssl genrsa 1024 > privkey.pem
    $ openssl rsa -pubout -in privkey.pem > pubkey.pem
    $ python ./gentlsa.py pubkey.pem
    _443._tcp.EXAMPLE.COM. 60 IN TYPE52 \# 35 020461757468303e3039060a2b06010401d67902

(Put this in your DNS zone, but don't forget to change "EXAMPLE.COM." to match the actual domain name. Once this is done, and the record is public, you can do the next step. You can check the record with `dig -t type52 example.com`.)

    $ python ./chain.py example.com chain
(Don't forget to change example.com to the actual domain name.)

    $ gcc -o gencert gencert.c -Wall -lcrypto
    $ ./gencert privkey.pem chain > cert.pem

(And, to check the certificate:)

    $ openssl x509 -text < cert.pem | less


Notes
-----
If you use rollerd to automagically roll your DNSSec keys you'll have to patch
your installed Net-DNS-ZoneFile-Fast with the provided patch.
