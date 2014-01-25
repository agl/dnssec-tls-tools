# This script spits out a TLSA record that can be used to authorize a public key
# for HTTPS in Chrome. The at moment it's limited to RSA public keys only.
# TODO(agl): support ECDSA public keys.
#
# It takes the public key and emits a record in a format that BIND understands.
#
# Usage: python ./gentlsa.py rsa_public_key.pem

import sys
import hashlib

# asn1Length returns an ASN.1 encoded length for 0 <= n < 65536.
def asn1Length(n):
  if n < 128:
    return chr(n)
  if n < 256:
    return '\x81' + chr(n)
  return '\x82' + chr(n >> 8) + chr(n & 0xff)

def main(args):
  if len(args) != 2:
    print 'usage: %s <RSA public key file>' % args[0]
    return

  base64_data = ''
  in_base64_data = False
  for line in [x[:-1] for x in file(args[1], 'r').readlines()]:
    if in_base64_data:
      if line == '-----END PUBLIC KEY-----':
        break
      base64_data += line
    elif line == '-----BEGIN PUBLIC KEY-----':
      in_base64_data = True

  if len(base64_data) == 0:
    print """Didn't find any RSA public key. Are you sure that you gave me a PEM encoded public key? It should look like like:
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYbj3exUKHRbRmHAeHshLuyX5L
+cr35LAKd3EbvRi/GjC8MbHKIRmW2Q11drPHzfnUxvIYYQPij7lkIZKux5D5RsmH
JEkG/diLA8llxX+UN6ZbkKghCT6GXLg2UO/d6biS8NHfZpz7XZgbBsV/T1O0BCum
KGz3vgkMv4tgKC8ghwIDAQAB
-----END PUBLIC KEY-----
"""
    return

  spki = base64_data.decode('base64')

  # This is a TLSA record which specifies a SHA256 hash of a
  # SubjectPublicKeyInfo.
  tlsa = '\x03\x01\x01'
  tlsa += hashlib.sha256(spki).digest()
  print '_443._tcp.EXAMPLE.COM. 60 IN TYPE52 \# %d %s' % (len(tlsa), tlsa.encode('hex'))

  print
  print "Don't forget to change the hostname to something sensible."

if __name__ == '__main__':
  main(sys.argv)

