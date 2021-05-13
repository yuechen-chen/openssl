/*-
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Example of using EVP_PKEY, EVP_MD* and EVP_Digest* methods to calculate
 * a signature using ecdsa
 */

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
#include "EVP_ECDSA_demo.inc"
#include "internal/nelem.h"

static OSSL_LIB_CTX *libctx = NULL;

static int ecdsa_create_pkey(EVP_PKEY **pkey, const char *curve_name,
                             const unsigned char *pub, size_t pub_len,
                             int expected)
{
    int ret = 0;
    /* The EVP_PKEY_CTX structure is an opaque public key algorithm context
     * used by the OpenSSL high-level public key API. 
     * See openssl/doc/man3/EVP_PKEY_CTX_new.pod for more details.
     */
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, 
                                    curve_name, 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                     pub, pub_len);
    params = OSSL_PARAM_BLD_to_param(bld);
    
    /* Allocates a public key algorithm context using the library context
     * libctx. See openssl/doc/man3/EVP_PKEY_CTX_new.pod for more details.
     */
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params);

    ret = 1;
    
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}


int ecdsa_demo(int id)
{
    int ret = 0;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    /* ECDSA_SIG is an opaque structure consisting of two BIGNUMs for the r and s 
     * value of an ECDSA signature. See  openssl/doc/man3/ECDSA_SIG_new.pod for
     * more details
     */
    ECDSA_SIG *sign = NULL;
    size_t sig_len;
    unsigned char *sig = NULL;
    BIGNUM *rbn = NULL, *sbn = NULL;
    const struct ecdsa_sigver_st *tst = &ecdsa_sigver_data[id];
    
    ecdsa_create_pkey(&pkey, tst->curve_name, tst->pub, tst->pub_len, 1);

    sign = ECDSA_SIG_new();
    rbn = BN_bin2bn(tst->r, tst->r_len, NULL);
    sbn = BN_bin2bn(tst->s, tst->s_len, NULL);
    ECDSA_SIG_set0(sign, rbn, sbn);

    rbn = sbn = NULL;
    sig_len = i2d_ECDSA_SIG(sign, &sig);
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit_ex(md_ctx, NULL,tst->digest_alg, 
                            libctx, NULL, pkey, NULL);
    ret = EVP_DigestVerify(md_ctx, sig, sig_len, tst->msg, tst->msg_len);

cleanup:
    BN_free(rbn);
    BN_free(sbn);
    OPENSSL_free(sig);
    ECDSA_SIG_free(sign);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

int main(void)
{
    int i = OSSL_NELEM(ecdsa_sigver_data);
    int id = 0;
    for( id; id< i; id++)
    {
      ecdsa_demo(id);
    }

}

