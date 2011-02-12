/**
 * NSS Engine - EVP keys
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

static EVP_PKEY*
nss_load_key(ENGINE *e, const char *key_id, int private, NSS_UI *wincx) {
    NSS_CTX          *ctx;
    CERTCertificate  *cert = NULL;
    SECKEYPrivateKey *pvtkey = NULL;
    SECKEYPublicKey  *pubkey = NULL;
    EVP_PKEY         *pkey = NULL;
    NSS_KEYCTX       *keyctx = NULL;

    ctx = ENGINE_get_ex_data(e, nss_eng_ctx_index);
    nss_verbose(ctx, "nss_load_key(): private=%d, key_id='%s'\n", private, key_id);

    if (!NSS_IsInitialized()) {
        nss_trace(ctx, "nss_load_key(): nss is not initialized\n");
        NSSerr(NSS_F_LOAD_KEY, NSS_R_DB_IS_NOT_INITIALIZED);
        goto done;
    }

    cert = PK11_FindCertFromNickname(key_id, NULL);
    if (cert == NULL) {
         NSSerr(NSS_F_LOAD_KEY, NSS_R_MISSING_CERT);
         goto done;
    }
    nss_debug(ctx, "nss_load_key(): The signer's certificate (%p) was found.\n", cert);

    if (private) {
        nss_trace(ctx, "nss_load_key(): wincx=%p\n", wincx);

        pvtkey = PK11_FindKeyByAnyCert(cert, wincx);
        nss_trace(ctx, "nss_load_key(): pvtkey=%p\n", pvtkey);
        if (pvtkey == NULL) {
            NSSerr(NSS_F_LOAD_KEY, NSS_R_MISSING_PVTKEY);
            goto done;
        }
    }

    pubkey = CERT_ExtractPublicKey(cert);
    nss_trace(ctx, "nss_load_key(): pubkey=%p\n", pubkey);
    if (pubkey == NULL) {
        NSSerr(NSS_F_LOAD_KEY, NSS_R_MISSING_PUBKEY);
        goto done;
    }

{
    SECItem* si_pubkey = PK11_DEREncodePublicKey(pubkey);

    if (si_pubkey == NULL) {
        NSSerr(NSS_F_LOAD_KEY, NSS_R_DERENCODE_PUBKEY);
        goto pubkeydone;
    }

    if (si_pubkey->type != siBuffer ) {
        NSSerr(NSS_F_LOAD_KEY, NSS_R_DERENCODE_PUBKEYBUF);
        goto pubkeydone;
    }

{
    long l = si_pubkey->len;
    void *q;
    const unsigned char *p;

    q = OPENSSL_malloc(l);
    if (q == NULL) {
        NSSerr(NSS_F_LOAD_KEY, NSS_R_INSUFFICIENT_MEMORY);
        goto pubkeydone;
    }
    p = q; /*use another pointer to avoid crash ;)*/

    memcpy(q, si_pubkey->data, l);
    nss_trace(ctx, "nss_load_key(): q=%p\n", q);

    pkey = d2i_PUBKEY(NULL, &p, l);
    nss_trace(ctx, "nss_load_key(): pkey=%p\n", pkey);

    OPENSSL_free(q);
}

pubkeydone:
    if (si_pubkey)
        SECITEM_FreeItem(si_pubkey, PR_TRUE);
}

    if (pkey == NULL) goto done;

    /* avoid errors as first check for key type */
    switch (pkey->type) {
    case EVP_PKEY_RSA: {
        RSA *pkey_rsa = EVP_PKEY_get1_RSA(pkey);

        if (ENGINE_get_RSA(e) == RSA_get_method(pkey_rsa)) {
            RSA_free(pkey_rsa);
            break;
        }

        /* if rsa method is not associated with this engine ... */
        {
            RSA *rsa = RSA_new_method(e);

            if (rsa == NULL) {
                    NSSerr(NSS_F_LOAD_KEY, NSS_R_INSUFFICIENT_MEMORY);
                    goto rsa_done;
            }

            rsa->n = BN_dup(pkey_rsa->n);
            rsa->e = BN_dup(pkey_rsa->e);
            if ((rsa->n == NULL) || (rsa->e == NULL)) {
                    NSSerr(NSS_F_LOAD_KEY, NSS_R_INSUFFICIENT_MEMORY);
                    goto rsa_done;
            }

            if (EVP_PKEY_set1_RSA(pkey, rsa)) {
                keyctx = RSA_get_ex_data(rsa, nss_rsa_ctx_index);
            }
rsa_done:
            RSA_free(rsa);
        }

        RSA_free(pkey_rsa);
        } break;

    default: {
        NSSerr(NSS_F_LOAD_KEY, NSS_R_UNSUPPORTED_KEYTYPE);
        { /* add extra error message data */
            char msgstr[10];
            BIO_snprintf(msgstr, sizeof(msgstr), "%d", pkey->type);
            ERR_add_error_data(2, "KEYTYPE=", msgstr);
        }
        EVP_PKEY_free(pkey);
        pkey = NULL;
        } break;
    }

    /* update XXX key context*/
    if (keyctx == NULL) {
        NSSerr(NSS_F_LOAD_KEY, NSS_R_MISSING_KEY_CONTEXT);
        goto done;
    }

    keyctx->cert = cert;
    cert = NULL;
    keyctx->pvtkey = pvtkey;
    pvtkey = NULL;
    keyctx->pubkey = pubkey;
    pubkey = NULL;

done:
    if (pubkey) {
        SECKEY_DestroyPublicKey(pubkey);
        pubkey = NULL;
    }
    if (pvtkey) {
        SECKEY_DestroyPrivateKey(pvtkey);
        pvtkey = NULL;
    }
    if (cert) {
        CERT_DestroyCertificate(cert);
        cert = NULL;
    }
    nss_trace(ctx, "nss_load_key()^ pkey=%p\n", pkey);
    return(pkey);
}


static EVP_PKEY*
nss_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
    NSS_CTX *ctx;
    NSS_UI   wincx = {ui_method, callback_data};

    ctx = ENGINE_get_ex_data(e, nss_eng_ctx_index);
    nss_verbose(ctx, "nss_load_privkey(%s)\n", key_id);

    return(nss_load_key(e, key_id, 1, &wincx));
}


static EVP_PKEY*
nss_load_pubkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
    NSS_CTX *ctx;
    NSS_UI   wincx = {ui_method, callback_data};

    ctx = ENGINE_get_ex_data(e, nss_eng_ctx_index);
    nss_verbose(ctx, "nss_load_pubkey(%s)\n", key_id);

    return(nss_load_key(e, key_id, 0, &wincx));
}
