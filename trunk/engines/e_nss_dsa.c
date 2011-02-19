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
    DSA_SIG*    ret = NULL;
    SECStatus   rv;
    NSS_CTX    *ctx;
    NSS_KEYCTX *keyctx;

    ctx = ENGINE_get_ex_data(dsa->engine, nss_eng_ctx_index);
    nss_trace(ctx, "nss_dsa_do_sign(dgst=%d, dlen=%d, ...)\n", dgst, dlen);

    keyctx = DSA_get_ex_data(dsa, nss_dsa_ctx_index);
    nss_trace(ctx, "nss_dsa_do_sign() keyctx=%p\n", keyctx);
    if (keyctx == NULL) {
        NSSerr(NSS_F_DSA_DO_SIGN, NSS_R_MISSING_KEY_CONTEXT);
        goto done;
    }

    nss_trace(ctx, "nss_dsa_do_sign() keyctx->prvkey=%p\n", keyctx->pvtkey);
    if (keyctx->pvtkey == NULL) {
        NSSerr(NSS_F_DSA_DO_SIGN, NSS_R_MISSING_PVTKEY);
        goto done;
    }

    if (dlen != 20) {
        NSSerr(NSS_F_DSA_DO_SIGN, NSS_R_INVALID_DIGEST_LENGTH);
        goto done;
    }

    nss_trace(ctx, "nss_dsa_do_sign() keyctx->pvtkey->keyType=%d\n", keyctx->pvtkey->keyType);
{
    SECItem    digest = { siBuffer, (unsigned char*)dgst, dlen };
    SECItem    result = { siBuffer, NULL, 0 };
    SECOidTag  hashalg /*= SEC_OID_SHA1 unused*/;

    rv = SGN_Digest(keyctx->pvtkey, hashalg, &result, &digest);
    nss_trace(ctx, "nss_dsa_do_sign() rv=%d\n", rv);
    if (rv != SECSuccess) {
        int port_err = PORT_GetError();
        switch(port_err) {
        default: {
            int port_err_off = port_err - SEC_ERROR_BASE;

            nss_trace(ctx, "nss_dsa_do_sign() port_err/ofset=%d/%d\n", port_err, port_err_off);
            NSSerr(NSS_F_DSA_DO_SIGN, NSS_R_SGN_DIGEST_FAIL);
            {/*add extra error message data*/
                char msgstr[10];
                BIO_snprintf(msgstr, sizeof(msgstr), "%d", port_err_off);
                ERR_add_error_data(2, "PORT_ERROR_OFFSET=", msgstr);
            }
            } break;
        }
        goto done;
    }


    /* propagate result */
    nss_trace(ctx, "nss_dsa_do_sign() result.len=%d\n", result.len);
    if (result.len != 40) {
        NSSerr(NSS_F_DSA_DO_SIGN, NSS_R_INVALID_SIGNATURE_LENGTH);
        goto done;
    }

    ret = DSA_SIG_new();
    if (ret == NULL) {
        NSSerr(NSS_F_DSA_DO_SIGN, NSS_R_INSUFFICIENT_MEMORY);
        goto done;
    }

    ret->r = BN_bin2bn(result.data   , 20, NULL);
    ret->s = BN_bin2bn(result.data+20, 20, NULL);
    if ((ret->r == NULL) || (ret->s == NULL)) {
        NSSerr(NSS_F_DSA_DO_SIGN, NSS_R_INSUFFICIENT_MEMORY);
        DSA_SIG_free(ret);
        ret = NULL;
    }
    OPENSSL_cleanse(result.data, 40);
}

done:
    return(ret);
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

    if (!ENGINE_set_DSA(e, &nss_dsa_method))
        return(0);
    return(1);
}
#endif /*ndef OPENSSL_NO_DSA*/
