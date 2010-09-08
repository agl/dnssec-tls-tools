#include <stdio.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static EVP_PKEY*
LoadKey(const char* filename) {
  BIO* infile = BIO_new(BIO_s_file());
  if (!infile) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if (BIO_read_filename(infile, filename) <= 0) {
    ERR_print_errors_fp(stderr);
    BIO_free(infile);
    return NULL;
  }

  EVP_PKEY* key = PEM_read_bio_PrivateKey(infile, NULL, NULL, NULL);
  BIO_free(infile);
  if (!key) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  return key;
}

static int
failure(const char* failing_func) {
  fprintf(stderr, "Failure in %s:\n", failing_func);
  ERR_print_errors_fp(stderr);
  return 1;
}

static ASN1_INTEGER*
RandInteger() {
  BIGNUM* bn = BN_new();
  ASN1_INTEGER* out = ASN1_INTEGER_new();

  if (!BN_pseudo_rand(bn, 64, 0, 0))
    goto error;
  if (!BN_to_ASN1_INTEGER(bn, out))
    goto error;

  goto done;

 error:
   ASN1_INTEGER_free(out);
   out = NULL;
 done:
   BN_free(bn);
   return out;
}

static int
usage(const char* argv0) {
  fprintf(stderr, "Usage: %s <public key file> <chain file> > cert.pem\n", argv0);
  return 1;
}

int
main(int argc, char** argv) {
  if (argc != 3)
    return usage(argv[0]);
  const char* key_filename = argv[1];
  const char* chain_filename = argv[2];

  EVP_PKEY* public_key = LoadKey(key_filename);
  if (!public_key)
    return 1;

  X509* x509 = X509_new();
  if (x509 == NULL)
    return failure("X509_new");
  if (!X509_set_version(x509, 3))
    return failure("X509_set_version");

  ASN1_INTEGER* serial = RandInteger();
  if (!serial)
    return failure("s2i_ASN1_INTEGER");
  X509_set_serialNumber(x509, serial);

  if (!X509_gmtime_adj(X509_get_notBefore(x509), 0))
    return failure("X509_gmtime_adj");
  if (!X509_gmtime_adj(X509_get_notAfter(x509), (long) 60*60*24*365))
    return failure("X509_gmtime_adj");

  X509_NAME* name = X509_NAME_new();
  if (!name)
    return failure("X509_NAME_new");
  if (!X509_NAME_add_entry_by_txt(name, "CN", V_ASN1_IA5STRING, "www.dnssec-exp.org", -1, -1, 0))
    return failure("X509_NAME_add_entry_by_txt");

  X509_set_subject_name(x509, name);
  X509_set_issuer_name(x509, name);

  if (!X509_set_pubkey(x509, public_key))
    return failure("X509_set_pubkey");

  // 1.3.6.1.4.1.11129.13172
  // (iso.org.dod.internet.private.enterprises.google.13172)
  static const unsigned char kChainExt[] =
      {0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0xe6, 0x74};
  ASN1_OBJECT chain_ext_obj = {"", "", 0, sizeof(kChainExt), (unsigned char*) kChainExt, 0};

  FILE* chain_file = fopen(chain_filename, "r");
  if (!chain_file) {
    perror("open chain file");
    return 1;
  }
  fseek(chain_file, 0, SEEK_END);
  unsigned long chain_len = ftell(chain_file);
  fseek(chain_file, 0, SEEK_SET);
  unsigned char *chain_data = malloc(chain_len);

  if (fread(chain_data, chain_len, 1, chain_file) != 1) {
    perror("read");
    return 1;
  }
  fclose(chain_file);

  ASN1_OCTET_STRING* chain_string = ASN1_OCTET_STRING_new();
  ASN1_OCTET_STRING_set(chain_string, chain_data, chain_len);

  X509_EXTENSION* ext = NULL;
  if (!X509_EXTENSION_create_by_OBJ(&ext, &chain_ext_obj, 0 /* not crit */, chain_string))
    return failure("X509_EXTENSION_create_by_OBJ");

  if (!X509_add_ext(x509, ext, -1))
    return failure("X509_add_ext");

  if (!X509_sign(x509, public_key, EVP_sha1()))
    return failure("X509_sign");

  BIO* out = BIO_new_fp(stdout, 0 /* don't close */);
  PEM_write_bio_X509(out, x509);
  BIO_free(out);

  return 0;
}
