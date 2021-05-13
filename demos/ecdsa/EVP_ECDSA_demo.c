#include <string.h>
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/self_test.h>
#include "acvp_test.inc"
#include "internal/nelem.h"




#define PASS 1
#define FAIL 0
#define ITM(x) x, sizeof(x)

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

typedef struct st_args {
    int enable;
    int called;
} SELF_TEST_ARGS;

static OSSL_PROVIDER *prov_null = NULL;
static OSSL_LIB_CTX *libctx = NULL;
static SELF_TEST_ARGS self_test_args = { 0 };
static OSSL_CALLBACK self_test_events;
/*
static int pkey_get_bn_bytes(EVP_PKEY *pkey, const char *name,
                             unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    BIGNUM *bn = NULL;
    int sz;

    if (!EVP_PKEY_get_bn_param(pkey, name, &bn))
        goto err;
    sz = BN_num_bytes(bn);
    buf = OPENSSL_zalloc(sz);
    if (buf == NULL)
        goto err;
    if (!BN_bn2binpad(bn, buf, sz))
        goto err;

    *out_len = sz;
    *out = buf;
    BN_free(bn);
    return 1;
err:
    OPENSSL_free(buf);
    BN_free(bn);
    return 0;
}

static int ecdsa_keygen_tesT(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *priv = NULL;
    unsigned char *pubx = NULL, *puby = NULL;
    size_t priv_len = 0, pubx_len = 0, puby_len = 0;
    const struct ecdsa_keygen_st *tst = &ecdsa_keygen_data[id];

    self_test_args.called = 0;
    self_test_args.enable = 1;
    if (pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", tst->curve_name)
        || self_test_args.called >=3
        || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv,
                                        &priv_len)
        || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &pubx,
                                        &pubx_len)
        || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &puby,
                                        &puby_len))
        goto err;

    ret = 1;
err:
    self_test_args.enable = 0;
    self_test_args.called = 0;
    OPENSSL_clear_free(priv, priv_len);
    OPENSSL_free(pubx);
    OPENSSL_free(puby);
    EVP_PKEY_free(pkey);
    return ret;
}
*/


static int ecdsa_keygen_tesT(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *priv = NULL;
    unsigned char *pubx = NULL, *puby = NULL;
    size_t priv_len = 0, pubx_len = 0, puby_len = 0;
    const struct ecdsa_keygen_st *tst = &ecdsa_keygen_data[id];

pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", tst->curve_name);



}

int main(int n)
{
     ecdsa_keygen_tesT(OSSL_NELEM(ecdsa_keygen_data));

}

