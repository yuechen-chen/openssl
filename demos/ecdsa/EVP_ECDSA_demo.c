# include <string.h>
# include <stdio.h>
# include <openssl/err.h>
# include "internal/deprecated.h"
# include <openssl/opensslconf.h> /* To see if OPENSSL_NO_EC is defined */
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/rand.h>
# include "internal/nelem.h"

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/self_test.h>





    static EC_builtin_curve *curves = NULL;
    static size_t crv_len = 0;

int demo_ecdsa(int n, int as)
{
    int nid = 0;
    EVP_MD_CTX *mctx = NULL;
    unsigned char tbs[128];
    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    int temp = 0;
    unsigned char *sig = NULL;
    size_t sig_len;
    

    crv_len = EC_get_builtin_curves(NULL, 0);
    curves = OPENSSL_malloc(sizeof(*curves) * crv_len);
    EC_get_builtin_curves(curves, crv_len);
    nid = curves[n].nid;
    mctx = EVP_MD_CTX_new();
    RAND_bytes(tbs, sizeof(tbs));
    eckey = EVP_PKEY_Q_keygen(mctx, NULL, "EC", nid);
    EC_KEY_generate_key(eckey);
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, eckey);

    temp = ECDSA_size(eckey);
    sig = OPENSSL_malloc(sig_len = (size_t)temp);
    EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey);
    EVP_DigestSign(mctx, sig, &sig_len, tbs, sizeof(tbs));
    EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey);
    EVP_DigestVerify(mctx, sig, sig_len, tbs, sizeof(tbs));
    EVP_MD_CTX_reset(mctx);
}

int main(int n)
{
    return demo_ecdsa(n, EVP_PKEY_SM2) == 0;
    return demo_ecdsa(n, EVP_PKEY_EC)  == 0;
}

