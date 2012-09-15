/* ecca_lib: Sign any certificate request with the provided CAcert and matching private CAkey
 * 
 * The task of this code is to sign a certificate if the username is unique.
 * We will sanitise the username before signing it.
 *
 * Inspired by code from openssl-1.0.1c/apps/ca.c, demos.
 */

// TODO: Focus on functionality to call it from Lua.
// TODO: Ignore memory leaks for now as we will run it in an NGINX http-lua module sandbox.


#include <string.h>
#include <stdio.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/safestack.h>


//************************
// Load CAkey (no password may be set)
EVP_PKEY* load_key_fh(FILE* fh) {
  EVP_PKEY *pkey = NULL;
  if (!PEM_read_PrivateKey(fh, &pkey, NULL, NULL)) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  return pkey;
}


//************************
// Load CAcert
X509* load_cert_fh(FILE* fh) {
  X509 *cert = NULL;
  if (!PEM_read_X509(fh, &cert, NULL, NULL)) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  return cert;
}

//************************
// Load the certificate signing request we want to sign
X509_REQ* load_csr_fh(FILE* fh) {
  X509_REQ* csr = NULL;
  if(!PEM_read_X509_REQ(fh, &csr, 0, NULL)) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  return csr;

  // show subject broken up in XX: value form
  /* for (int i=0; i < X509_NAME_entry_count(subject_name); i++) { */
  /*   X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, i); */
  /*   ASN1_OBJECT* object = X509_NAME_ENTRY_get_object(entry); */
  /*   int nid = OBJ_obj2nid(object); */
  /*   const char* lngname = OBJ_nid2ln(nid); */

  /*   ASN1_STRING* asn1 = X509_NAME_ENTRY_get_data(entry); */
  /*   unsigned char *name = NULL; */
  /*   int len = ASN1_STRING_to_UTF8(&name, asn1); */
  /*   fprintf(stderr, "read CSR, subject is (%s): (%s)\n", lngname, name); */
  /* } */
}


//************************
// split value in "key:val" and give it to EVP
int pkey_ctrl_string(EVP_PKEY_CTX *ctx, char *value) {
  int rv;
  char *stmp, *vtmp = NULL;
  stmp = BUF_strdup(value);
  if (!stmp)
    return -1;
  vtmp = strchr(stmp, ':');
  if (vtmp)
    {
      *vtmp = 0; // replace ':' with \0 to end key (stmp)
      vtmp++;    // start of val (vtmp)
    }
  rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
  OPENSSL_free(stmp);
  return rv;
}


//************************
// 
static int do_sign_init(BIO *err, EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts) {
  EVP_PKEY_CTX *pkctx = NULL;
  EVP_MD_CTX_init(ctx);
  if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
    return 0;
  int i=0;
  for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++)
    {
      char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
      if (pkey_ctrl_string(pkctx, sigopt) <= 0)
	{
	  BIO_printf(err, "parameter error \"%s\"\n", sigopt);
	  ERR_print_errors(err);
	  return 0;
	}
    }
  return 1;
}

//************************
// 
int do_X509_sign(BIO *err, X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                        STACK_OF(OPENSSL_STRING) *sigopts) {
  int rv;
  EVP_MD_CTX mctx;
  EVP_MD_CTX_init(&mctx);
  rv = do_sign_init(err, &mctx, pkey, md, sigopts);
  if (rv > 0)
    rv = X509_sign_ctx(x, &mctx);
  EVP_MD_CTX_cleanup(&mctx);
  return rv > 0 ? 1 : 0;
}


//************************
// 
int add_ext(X509 *cert, int nid, char *value)
{
  // TODO: add configs in a lua-table and let it get read by X509V3_CTX->db_meth functions.
  X509V3_CTX ctx; // This sets the 'context' of the extensions. 
  X509V3_set_ctx_nodb(&ctx); // No configuration database 
  // set cl_cert in the context, leave out cacert, csr
  X509V3_set_ctx(&ctx, NULL, cert, NULL, NULL, 0);

  X509_EXTENSION* ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
  if (!ex)
    return 0;

  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  return 1;
}


//************************
// Sign the request from a CSR
X509* csr_sign(EVP_PKEY* cakey, X509* cacert, X509_REQ* csr) {
  
  // to show errors
  BIO* err=BIO_new_fp(stderr, BIO_NOCLOSE);

  // get the subject from the csr
  X509_NAME* subject_name = X509_REQ_get_subject_name(csr);
  // this is probably not i18n-safe, see X509_NAME_get_index_by_NID(3)
  unsigned char cn[128];
  int got_cn = X509_NAME_get_text_by_NID(subject_name, NID_commonName, (char*)cn, 127);
 
  // create an empty client certificate and populate it
  X509* cl_cert = X509_new();
  X509_CINF* ci = cl_cert->cert_info;

  // Make it an X509 v3 certificate.
  X509_set_version(cl_cert,2);

  // set the commonName in the subject
  X509_NAME* subj = X509_NAME_new();
  X509_NAME_add_entry_by_NID(subj, NID_commonName, MBSTRING_ASC, cn, -1, -1, 0);
  X509_set_subject_name(cl_cert, subj);

  // set the client's public key
  EVP_PKEY* pubk_tmp=X509_REQ_get_pubkey(csr);
  X509_set_pubkey(cl_cert, pubk_tmp);
  EVP_PKEY_free(pubk_tmp);

  // Set serial randomly.
  BIGNUM* serial = BN_new();
  BN_rand(serial, 64, -1, 0);
  BN_to_ASN1_INTEGER(serial, ci->serialNumber);

  // set issuer with cacert-subject
  X509_set_issuer_name(cl_cert, X509_get_subject_name(cacert));

  // set validation times (TODO: set start at start of CA and end at end of CA for anonymyzing purpose)
  X509_gmtime_adj(X509_get_notBefore(cl_cert),0); // start date is today
  X509_time_adj_ex(X509_get_notAfter(cl_cert), 14, 0, NULL); // valid for 14 days
  // ASN1_TIME_set_string(X509_get_notBefore(cl_cert), startdate);
  // ASN1_TIME_set_string(X509_get_notAfter(cl_cert),  enddate);

  // set extensions
  add_ext(cl_cert, NID_basic_constraints, "critical,CA:FALSE");
  add_ext(cl_cert, NID_key_usage, "nonRepudiation, digitalSignature, keyEncipherment");
  add_ext(cl_cert, NID_ext_key_usage, "clientAuth");
  add_ext(cl_cert, NID_subject_key_identifier, "hash");
  add_ext(cl_cert, NID_authority_key_identifier, "keyid, issuer");

  // set Netscape extensions
  add_ext(cl_cert, NID_netscape_cert_type, "client, email");
  add_ext(cl_cert, NID_netscape_comment, "Eccentric Authority CA");
  

  // sign it
  int rv = do_X509_sign(err, cl_cert, cakey, EVP_sha1(), /* STACK_OF(OPENSSL_STRING) *sigopts */ NULL);



  return cl_cert;
}

//************************
// Sign the request from a CN and a Public Key
X509* cn_key_sign(EVP_PKEY* cakey, X509* cacert, char* cn, EVP_PKEY* pubkey) {
  
  // to show errors
  BIO* err=BIO_new_fp(stderr, BIO_NOCLOSE);
 
  // create an empty client certificate and populate it
  X509* cl_cert = X509_new();
  X509_CINF* ci = cl_cert->cert_info;

  // Make it an X509 v3 certificate.
  X509_set_version(cl_cert,2);

  // set the commonName in the subject
  X509_NAME* subj = X509_NAME_new();
  X509_NAME_add_entry_by_NID(subj, NID_commonName, MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0);
  X509_set_subject_name(cl_cert, subj);

  // set the client's public key
  X509_set_pubkey(cl_cert, pubkey);

  // set serial random to prevent creating a 
  // As long as it's unique. We don't bother to check as the cn is the primary key.
  BIGNUM* serial = BN_new();
  // TODO: make sure we 
  BN_rand(serial, 64, -1, 0);
  BN_to_ASN1_INTEGER(serial, ci->serialNumber);

  // set issuer with cacert-subject
  X509_set_issuer_name(cl_cert, X509_get_subject_name(cacert));

  // set validation times (TODO: set start at start of CA and end at end of CA for anonymyzing purpose)
  X509_gmtime_adj(X509_get_notBefore(cl_cert),0); // start date is today
  X509_time_adj_ex(X509_get_notAfter(cl_cert), 14, 0, NULL); // valid for 14 days
  // ASN1_TIME_set_string(X509_get_notBefore(cl_cert), startdate);
  // ASN1_TIME_set_string(X509_get_notAfter(cl_cert),  enddate);

  // set extensions
  add_ext(cl_cert, NID_basic_constraints, "critical,CA:FALSE");
  add_ext(cl_cert, NID_key_usage, "nonRepudiation, digitalSignature, keyEncipherment");
  add_ext(cl_cert, NID_ext_key_usage, "clientAuth");
  add_ext(cl_cert, NID_subject_key_identifier, "hash");
  add_ext(cl_cert, NID_authority_key_identifier, "keyid, issuer");

  // set Netscape extensions
  add_ext(cl_cert, NID_netscape_cert_type, "client, email");
  add_ext(cl_cert, NID_netscape_comment, "Eccentric Authority CA");
  

  // sign it
  int rv = do_X509_sign(err, cl_cert, cakey, EVP_sha1(), /* STACK_OF(OPENSSL_STRING) *sigopts */ NULL);

  return cl_cert;
}


// And now call from Lua

#define LUA_FUNCTION(X) static int X (lua_State* L)

LUA_FUNCTION(l_parse_csr) {
  // read a pem-encoded csr string and return a table containing:
  // { CN = "username", O = "organisation", ... }

  size_t csr_length = 0;
  const char* csr_str = luaL_checklstring(L, 1, &csr_length);
  BIO* csr_bio = BIO_new_mem_buf((void*) csr_str, csr_length);
  X509_REQ* csr = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
  if (! csr) {
    BIO *err = BIO_new(BIO_s_mem());
    BIO_puts(err, "Error decoding certificate signing request\n");
    ERR_print_errors(err);
    char* err_str = NULL;
    long err_str_size = BIO_get_mem_data(err, &err_str);
    luaL_error(L, err_str);
  }

  lua_newtable(L);
  X509_NAME* subject = X509_REQ_get_subject_name(csr);
  int i=0;
  for (i=0; i < X509_NAME_entry_count(subject); i++) {
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, i);
    ASN1_OBJECT* object = X509_NAME_ENTRY_get_object(entry);
    int nid = OBJ_obj2nid(object);
    const char* key = OBJ_nid2sn(nid);

    ASN1_STRING* asn1 = X509_NAME_ENTRY_get_data(entry);
    unsigned char *value = NULL;
    int len = ASN1_STRING_to_UTF8(&value, asn1);
    
    lua_pushstring(L, key);
    lua_pushstring(L, (char*) value);  //, len);
    lua_settable(L, -3);
  }
  return 1; // return the table
}


LUA_FUNCTION(l_sign_csr) {
  // load cakey from arg[1]
  size_t cakey_length = 0;
  const char* cakey_str = luaL_checklstring(L, 1, &cakey_length);
  BIO* cakey_bio = BIO_new_mem_buf((void*) cakey_str, cakey_length);
  EVP_PKEY* cakey = PEM_read_bio_PrivateKey(cakey_bio, NULL, NULL, NULL);
  if (! cakey) {
    BIO *err = BIO_new(BIO_s_mem());
    BIO_puts(err, "Error decoding private key\n");
    ERR_print_errors(err);
    char* err_str = NULL;
    long err_str_size = BIO_get_mem_data(err, &err_str);
    luaL_error(L, err_str);
  }
  
  // load cacert from arg[2]
  size_t cacert_length = 0;
  const char* cacert_str = luaL_checklstring(L, 2, &cacert_length);
  BIO* cacert_bio = BIO_new_mem_buf((void*) cacert_str, cacert_length);
  X509* cacert = PEM_read_bio_X509(cacert_bio, NULL, NULL, NULL);
  if (! cacert) {
    BIO *err = BIO_new(BIO_s_mem());
    BIO_puts(err, "Error decoding certificate\n");
    ERR_print_errors(err);
    char* err_str = NULL;
    long err_str_size = BIO_get_mem_data(err, &err_str);
    luaL_error(L, err_str);
  }
  
  // Check that CAkey and CAcert match before proceeding. TODO: move this test to startup...
  if (!X509_check_private_key(cacert, cakey))
    {
      // ERR_print_errors_fp(stderr); 
      // this error is unreadable!
      // it reads: 37543:error:0B080074:lib(11):func(128):reason(116):/SourceCache/OpenSSL098/OpenSSL098-35.1/src/crypto/x509/x509_cmp.c:406:
      // give a better one:
      luaL_error(L, "CA certificate and CA private key do not match!");
    }

  // load CSR from arg[3]
  size_t csr_length = 0;
  const char* csr_str = luaL_checklstring(L, 3, &csr_length);
  BIO* csr_bio = BIO_new_mem_buf((void*) csr_str, csr_length);
  X509_REQ* csr = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
  if (! csr) {
    BIO *err = BIO_new(BIO_s_mem());
    BIO_puts(err, "Error decoding certificate signing request\n");
    ERR_print_errors(err);
    char* err_str = NULL;
    long err_str_size = BIO_get_mem_data(err, &err_str);
    luaL_error(L, err_str);
  }


  // sign it!
  X509* cl_cert = csr_sign(cakey, cacert, csr);

  if (cl_cert) {
    // return the pem-encoded certificate first
    BIO *mem1 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem1, cl_cert);
    char* cl_cert_str;
    long cl_cert_size = BIO_get_mem_data(mem1, &cl_cert_str);
    lua_pushlstring(L, cl_cert_str, cl_cert_size);

    // add the text-output second.
    BIO *mem2 = BIO_new(BIO_s_mem());
    X509_print(mem2, cl_cert);
    char* cl_text_str;
    long cl_text_size = BIO_get_mem_data(mem2, &cl_text_str);
    lua_pushlstring(L, cl_text_str, cl_text_size);
    return 2;
  } else {
    luaL_error(L, "error signing certificate"); // TODO: return bio-err from the C-function
    /* NOTREACHED */ return 0;
  }
}

// send an error message upstream. Include the OpenSSL error.
void send_error(lua_State* L, const char* message) {
  BIO *err = BIO_new(BIO_s_mem());
  BIO_puts(err, message);
  ERR_print_errors(err);
  char* err_str = NULL;
  long err_str_size = BIO_get_mem_data(err, &err_str);
  luaL_error(L, err_str);
}


LUA_FUNCTION(l_sign_cn_key) {
  // load cakey from arg[1]
  size_t cakey_length = 0;
  const char* cakey_str = luaL_checklstring(L, 1, &cakey_length);
  BIO* cakey_bio = BIO_new_mem_buf((void*) cakey_str, cakey_length);
  EVP_PKEY* cakey = PEM_read_bio_PrivateKey(cakey_bio, NULL, NULL, NULL);
  if (! cakey) {
    send_error(L, "Error decoding private key\n");
  }
  
  // load cacert from arg[2]
  size_t cacert_length = 0;
  const char* cacert_str = luaL_checklstring(L, 2, &cacert_length);
  BIO* cacert_bio = BIO_new_mem_buf((void*) cacert_str, cacert_length);
  X509* cacert = PEM_read_bio_X509(cacert_bio, NULL, NULL, NULL);
  if (! cacert) {
    send_error(L, "Error decoding certificate\n");
  }
  
  // Check that CAkey and CAcert match before proceeding. TODO: move this test to startup...
  if (!X509_check_private_key(cacert, cakey))
    {
      // ERR_print_errors_fp(stderr)  is unreadable!!
      // it reads: 37543:error:0B080074:lib(11):func(128):reason(116):/SourceCache/OpenSSL098/OpenSSL098-35.1/src/crypto/x509/x509_cmp.c:406:
      // give a better one:
      luaL_error(L, "CA certificate and CA private key do not match!");
    }

  //  CN is arg[3]
  size_t cn_length = 0;
  char* cn = (char*) luaL_checklstring(L, 3, &cn_length);

  // Client's public key is arg[4]
  size_t key_length = 0;
  const char* pubkey_str = luaL_checklstring(L, 4, &key_length);
  BIO* pubkey_bio = BIO_new_mem_buf((void*) pubkey_str, key_length);
  EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(pubkey_bio, NULL, NULL, NULL);
  if (! pubkey) {
    send_error(L, "Error decoding public key\n");
  }
  // sign it!
  X509* cl_cert = cn_key_sign(cakey, cacert, cn, pubkey);

  if (cl_cert) {
    // return the pem-encoded certificate first
    BIO *mem1 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem1, cl_cert);
    char* cl_cert_str;
    long cl_cert_size = BIO_get_mem_data(mem1, &cl_cert_str);
    lua_pushlstring(L, cl_cert_str, cl_cert_size);

    // add the text-output second.
    BIO *mem2 = BIO_new(BIO_s_mem());
    X509_print(mem2, cl_cert);
    char* cl_text_str;
    long cl_text_size = BIO_get_mem_data(mem2, &cl_text_str);
    lua_pushlstring(L, cl_text_str, cl_text_size);
    return 2;
  } else {
    luaL_error(L, "error signing certificate"); // TODO: return bio-err from the C-function
    /* NOTREACHED */ return 0;
  }
}

LUA_FUNCTION(l_sign_cn_spkac) {
  // load cakey from arg[1]
  size_t cakey_length = 0;
  const char* cakey_str = luaL_checklstring(L, 1, &cakey_length);
  BIO* cakey_bio = BIO_new_mem_buf((void*) cakey_str, cakey_length);
  EVP_PKEY* cakey = PEM_read_bio_PrivateKey(cakey_bio, NULL, NULL, NULL);
  if (! cakey) {
    send_error(L, "Error decoding private key\n");
  }
  
  // load cacert from arg[2]
  size_t cacert_length = 0;
  const char* cacert_str = luaL_checklstring(L, 2, &cacert_length);
  BIO* cacert_bio = BIO_new_mem_buf((void*) cacert_str, cacert_length);
  X509* cacert = PEM_read_bio_X509(cacert_bio, NULL, NULL, NULL);
  if (! cacert) {
    send_error(L, "Error decoding certificate\n");
  }
  
  // Check that CAkey and CAcert match before proceeding. TODO: move this test to startup...
  if (!X509_check_private_key(cacert, cakey))
    {
      // ERR_print_errors_fp(stderr)  is unreadable!!
      // it reads: 37543:error:0B080074:lib(11):func(128):reason(116):/SourceCache/OpenSSL098/OpenSSL098-35.1/src/crypto/x509/x509_cmp.c:406:
      // give a better one:
      luaL_error(L, "CA certificate and CA private key do not match!");
    }

  //  CN is arg[3]
  size_t cn_length = 0;
  char* cn = (char*) luaL_checklstring(L, 3, &cn_length);

  // Client's spkac is arg[4]
  size_t sp_length = 0;
  const char* spkac_str = luaL_checklstring(L, 4, &sp_length);
  NETSCAPE_SPKI *spki = NULL;
  spki = NETSCAPE_SPKI_b64_decode(spkac_str, sp_length);
  if (! spki) {
    send_error(L, "Cannot decode Public Key data. Please provide a valid SPKAC structure.");
  }
  
  //BIO* pubkey_bio = BIO_new_mem_buf((void*) spkac_str, sp_length);
  //EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(pubkey_bio, NULL, NULL, NULL);
  EVP_PKEY* pubkey = NETSCAPE_SPKI_get_pubkey(spki);
  if (! pubkey) {
    send_error(L, "Error decoding public key\n");
  }
  // TODO: validate SPKAC with challenge.  

  // sign it!
  X509* cl_cert = cn_key_sign(cakey, cacert, cn, pubkey);

  if (cl_cert) {
    // return the pem-encoded certificate first
    BIO *mem1 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem1, cl_cert);
    char* cl_cert_str;
    long cl_cert_size = BIO_get_mem_data(mem1, &cl_cert_str);
    lua_pushlstring(L, cl_cert_str, cl_cert_size);

    // add the text-output second.
    BIO *mem2 = BIO_new(BIO_s_mem());
    X509_print(mem2, cl_cert);
    char* cl_text_str;
    long cl_text_size = BIO_get_mem_data(mem2, &cl_text_str);
    lua_pushlstring(L, cl_text_str, cl_text_size);
    return 2;
  } else {
    luaL_error(L, "error signing certificate"); // TODO: return bio-err from the C-function
    /* NOTREACHED */ return 0;
  }
}

// The function table
static const struct luaL_Reg ecca_functions [] = {
  {"parse_csr",     l_parse_csr},
  {"sign_csr",      l_sign_csr},
  {"sign_cn_key",   l_sign_cn_key},
  {"sign_cn_spkac", l_sign_cn_spkac},
  {NULL, NULL}
};

// The library initialiser
// Lua require("module") expects: luaopen_<module>
int luaopen_ecca_lib(lua_State *L) {
  luaL_register(L, "ecca_lib", ecca_functions);
  //luaL_newlib(L, ecca_functions); // Lua 5.2
  return 1;
}
