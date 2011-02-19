/**
 * NSS Engine - DSA method
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

#ifndef OPENSSL_NO_DSA
static DSA_SIG*
nss_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa) {
    return(NULL);
}


static int
nss_dsa_init(DSA *dsa) {
    int ret = 0;

    CALL_TRACE("nss_dsa_init():\n");

    {/*setup NSS DSA key context*/
        NSS_KEYCTX *keyctx = NSS_KEYCTX_new();

        if (keyctx == NULL) {
            NSSerr(NSS_F_DSA_INIT, NSS_R_INSUFFICIENT_MEMORY);
            goto done;
        }
        DSA_set_ex_data(dsa, nss_dsa_ctx_index, keyctx);
    }

    ret = 1;
done:
    CALL_TRACE("nss_dsa_init() %s^\n", (ret ? "ok": ""));
    return(ret);
}


static int
nss_dsa_finish(DSA *dsa) {
    int ret = 0;
    NSS_KEYCTX *keyctx;

    CALL_TRACE("nss_dsa_finish:\n");

    keyctx = DSA_get_ex_data(dsa, nss_dsa_ctx_index);
    if (keyctx == NULL) {
        NSSerr(NSS_F_DSA_FINISH, NSS_R_MISSING_KEY_CONTEXT);
        goto done;
    }
    DSA_set_ex_data(dsa, nss_dsa_ctx_index, NULL);
    NSS_KEYCTX_free(keyctx);

    ret = 1;
done:
    CALL_TRACE("nss_dsa_finish %s^\n", (ret ? "ok": ""));
    return(ret);
}


static DSA_METHOD
nss_dsa_method = {
    "NSS PKCS#1 DSA method",
    nss_dsa_do_sign,
    NULL  /* dsa_sign_setup */,
    NULL  /* same as DSA_OpenSSL()->dsa_do_verify */,
    NULL  /* same as DSA_OpenSSL()->dsa_mod_exp */,
    NULL  /* same as DSA_OpenSSL()->bn_mod_exp */,
    nss_dsa_init,
    nss_dsa_finish,
    0  /* int flags; */,
    NULL  /* app_data */,
    NULL  /* dsa_paramgen */,
    NULL  /* dsa_keygen */
};


static int/*bool*/
bind_nss_dsa_method(ENGINE *e) {
    const DSA_METHOD *dsa_method = DSA_OpenSSL();

    CALL_TRACE("bind_nss_dsa_method() dsa_method=%p\n", dsa_method);
    nss_dsa_method.dsa_do_verify = dsa_method->dsa_do_verify;
    nss_dsa_method.dsa_mod_exp = dsa_method->dsa_mod_exp;
    nss_dsa_method.bn_mod_exp  = dsa_method->bn_mod_exp;

#if 0 /* not yet */
    if (!ENGINE_set_DSA(e, &nss_dsa_method))
        return(0);
#endif
    return(1);
}
#endif /*ndef OPENSSL_NO_DSA*/
