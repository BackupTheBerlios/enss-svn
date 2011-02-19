/**
 * NSS Engine - RSA method
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

#ifndef OPENSSL_NO_RSA
static int
nss_rsa_priv_enc(int len, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    NSSerr(NSS_F_RSA_PRIV_ENC, NSS_R_NOT_SUPPORTED);
    return(-1);
}


static int
nss_rsa_priv_dec(int len, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    int         ret = 0;
    NSS_CTX    *ctx;
    NSS_KEYCTX *keyctx;

    switch(padding) {
    case RSA_NO_PADDING:
    case RSA_PKCS1_PADDING: break;
    default: {
        NSSerr(NSS_F_RSA_PRIV_DEC, NSS_R_UNSUPPORTED_PADDING);
        {/*add extra error message data*/
            char msgstr[10];
            BIO_snprintf(msgstr, sizeof(msgstr), "%d", padding);
            ERR_add_error_data(2, "PADDING=", msgstr);
        }
        goto done;
        } break;
    }
    ctx = ENGINE_get_ex_data(rsa->engine, nss_eng_ctx_index);
    keyctx = RSA_get_ex_data(rsa, nss_rsa_ctx_index);

    nss_trace(ctx, "nss_rsa_priv_dec() keyctx=%p\n", keyctx);
    if (keyctx == NULL) {
        NSSerr(NSS_F_RSA_PRIV_DEC, NSS_R_MISSING_KEY_CONTEXT);
        goto done;
    }
    nss_trace(ctx, "nss_rsa_priv_dec() keyctx->prvkey=%p\n", keyctx->pvtkey);
    if (keyctx->pvtkey == NULL) {
        NSSerr(NSS_F_RSA_PRIV_DEC, NSS_R_MISSING_PVTKEY);
        goto done;
    }

    {
        SECStatus      rv = SECFailure;
        unsigned char *enc = (unsigned char*)from;
        unsigned int   outLen;
        unsigned int   maxLen = RSA_size(rsa);

        switch(padding) {
        case RSA_NO_PADDING   : rv = PK11_PubDecryptRaw   (keyctx->pvtkey, to, &outLen, maxLen, enc, len);  break;
        case RSA_PKCS1_PADDING: rv = PK11_PrivDecryptPKCS1(keyctx->pvtkey, to, &outLen, maxLen, enc, len);  break;
        }
        if (rv != SECSuccess) {
            NSSerr(NSS_F_RSA_PRIV_DEC, NSS_R_DECRYPT_FAIL);
            goto done;
        }
        ret = outLen;
    }
done:
    return(ret);
}


static int
nss_rsa_init(RSA *rsa) {
    int ret = 0;

    CALL_TRACE("nss_rsa_init():\n");

    {/*setup NSS RSA key context*/
        NSS_KEYCTX *keyctx = NSS_KEYCTX_new();

        if (keyctx == NULL) {
            NSSerr(NSS_F_RSA_INIT, NSS_R_INSUFFICIENT_MEMORY);
            goto done;
        }
        RSA_set_ex_data(rsa, nss_rsa_ctx_index, keyctx);
    }

    ret = 1;
done:
    CALL_TRACE("nss_rsa_init() %s^\n", (ret ? "ok": ""));
    return(ret);
}


static int
nss_rsa_finish(RSA *rsa) {
    int ret = 0;
    NSS_KEYCTX *keyctx;

    CALL_TRACE("nss_rsa_finish:\n");

    keyctx = RSA_get_ex_data(rsa, nss_rsa_ctx_index);
    if (keyctx == NULL) {
        NSSerr(NSS_F_RSA_FINISH, NSS_R_MISSING_KEY_CONTEXT);
        goto done;
    }
    RSA_set_ex_data(rsa, nss_rsa_ctx_index, NULL);
    NSS_KEYCTX_free(keyctx);

    ret = 1;
done:
    CALL_TRACE("nss_rsa_finish %s^\n", (ret ? "ok": ""));
    return(ret);
}


int/*bool*/
nss_rsa_sign(int dtype, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa) {
    int         ret = 0;
    SECStatus   rv;
    NSS_CTX    *ctx;
    NSS_KEYCTX *keyctx;

    ctx = ENGINE_get_ex_data(rsa->engine, nss_eng_ctx_index);
    nss_trace(ctx, "nss_rsa_sign(dtype=%d, m=%p, m_length=%d, ...)\n", dtype, m, m_length);
    nss_trace(ctx, "nss_rsa_sign() rsa=%p, meth=%p, name=%s\n", rsa, rsa->meth, rsa->meth->name);

    keyctx = RSA_get_ex_data(rsa, nss_rsa_ctx_index);
    nss_trace(ctx, "nss_rsa_sign() keyctx=%p\n", keyctx);
    if (keyctx == NULL) {
        NSSerr(NSS_F_RSA_SIGN, NSS_R_MISSING_KEY_CONTEXT);
        goto done;
    }

    nss_trace(ctx, "nss_rsa_sign() keyctx->prvkey=%p\n", keyctx->pvtkey);
    if (keyctx->pvtkey == NULL) {
        NSSerr(NSS_F_RSA_SIGN, NSS_R_MISSING_PVTKEY);
        goto done;
    }

    nss_trace(ctx, "nss_rsa_sign() keyctx->pvtkey->keyType=%d\n", keyctx->pvtkey->keyType);

{
    SECItem    digest = { siBuffer, (unsigned char*)m, m_length };
    SECItem    result = { siBuffer, NULL, 0 };
    SECOidTag  hashalg;

    switch (dtype) {
    case NID_md2        : hashalg = SEC_OID_MD2   ; break;
    case NID_md5        : hashalg = SEC_OID_MD5   ; break;
    case NID_sha1       : hashalg = SEC_OID_SHA1  ; break;
    case NID_sha256     : hashalg = SEC_OID_SHA256; break;
    case NID_sha384     : hashalg = SEC_OID_SHA384; break;
    case NID_sha512     : hashalg = SEC_OID_SHA512; break;
    default : {
        NSSerr(NSS_F_RSA_SIGN, NSS_R_UNSUPPORTED_NID);
        {/*add extra error message data*/
            char msgstr[10];
            BIO_snprintf(msgstr, sizeof(msgstr), "%d", dtype);
            ERR_add_error_data(2, "NID=", msgstr);
        }
        goto signdone;
        } break;
    }

    nss_trace(ctx, "nss_rsa_sign()   sigret=%p, *siglen=%d\n", sigret, *siglen);

/* NOTE:
 * - If we use PK11_Sign here we must use PK11_Verify later
 *   but the signed data is not compatible with openssl
 * - SEC_SignData may be hash again hash data
 *   http://www.mail-archive.com/dev-tech-crypto@lists.mozilla.org/msg09116.html
 */
#if 0
/*
** Sign a single block of data using private key encryption and given
** signature/hash algorithm.
**	"result" the final signature data (memory is allocated)
**	"buf" the input data to sign
**	"len" the amount of data to sign
**	"pk" the private key to encrypt with
**	"algid" the signature/hash algorithm to sign with 
**		(must be compatible with the key type).
*/
extern SECStatus SEC_SignData(SECItem *result,
			     const unsigned char *buf, int len,
			     SECKEYPrivateKey *pk, SECOidTag algid);
#endif
    rv = SGN_Digest(keyctx->pvtkey, hashalg, &result, &digest);
    nss_trace(ctx, "nss_rsa_sign() rv=%d\n", rv);
    if (rv != SECSuccess) {
        int port_err = PORT_GetError();
        switch(port_err) {
        case SEC_ERROR_INVALID_ALGORITHM: {
            nss_trace(ctx, "nss_rsa_sign()   SEC_ERROR_INVALID_ALGORITHM\n");
            NSSerr(NSS_F_RSA_SIGN, NSS_R_INVALID_ALGORITHM);
            } break;
        default: {
            int port_err_off = port_err - SEC_ERROR_BASE;

            nss_trace(ctx, "nss_rsa_sign() port_err/ofset=%d/%d\n", port_err, port_err_off);
            NSSerr(NSS_F_RSA_SIGN, NSS_R_SGN_DIGEST_FAIL);
            {/*add extra error message data*/
                char msgstr[10];
                BIO_snprintf(msgstr, sizeof(msgstr), "%d", port_err_off);
                ERR_add_error_data(2, "PORT_ERROR_OFFSET=", msgstr);
            }
            } break;
        }
        goto signdone;
    }

    { /* propagate result */
        int len = result.len;

        nss_trace(ctx, "nss_rsa_sign() len=%d sigret=%p\n", len, sigret);
        memcpy(sigret, result.data, len);
        *siglen = len;
    }

    ret = 1;
signdone:
    if (result.data != NULL) {
        PORT_Free(result.data);
    }
}

done:
    nss_trace(ctx, "nss_rsa_sign() ret=%d\n", ret);
    return(ret);
}


int/*bool*/
nss_rsa_verify(int dtype, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa) {
    int         ret = 0;
    SECStatus   rv;
    NSS_CTX    *ctx;
    NSS_KEYCTX *keyctx;

    ctx = ENGINE_get_ex_data(rsa->engine, nss_eng_ctx_index);
    nss_trace(ctx, "nss_rsa_verify(dtype=%d, ...)\n", dtype);
    nss_trace(ctx, "nss_rsa_verify() rsa=%p, meth=%p, name=%s\n", rsa, rsa->meth, rsa->meth->name);

    keyctx = RSA_get_ex_data(rsa, nss_rsa_ctx_index);
    nss_trace(ctx, "nss_rsa_verify() keyctx=%p\n", keyctx);
    if (keyctx == NULL) {
        NSSerr(NSS_F_RSA_VERIFY, NSS_R_MISSING_KEY_CONTEXT);
        goto done;
    }

    nss_trace(ctx, "nss_rsa_verify() keyctx->pubkey=%p\n", keyctx->pubkey);
    if (keyctx->pubkey == NULL) {
        NSSerr(NSS_F_RSA_VERIFY, NSS_R_MISSING_PUBKEY);
        goto done;
    }

    nss_trace(ctx, "nss_rsa_verify() keyctx->pubkey->keyType=%d\n", keyctx->pubkey->keyType);

{
    SECItem    digest = { siBuffer, (unsigned char*)m, m_length };
    SECItem    sig    = { siBuffer, (unsigned char*)sigbuf, siglen };
    SECOidTag  algid;
    void      *wincx  = NULL;

    switch (dtype) {
    case NID_md2        : algid = SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION   ; break;
    case NID_md5        : algid = SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION   ; break;
    case NID_sha1       : algid = SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION  ; break;
    case NID_sha256     : algid = SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION; break;
    case NID_sha384     : algid = SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION; break;
    case NID_sha512     : algid = SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION; break;
    default : {
        NSSerr(NSS_F_RSA_VERIFY, NSS_R_UNSUPPORTED_NID);
        {/* add extra error message data*/
            char msgstr[10];
            BIO_snprintf(msgstr, sizeof(msgstr), "%d", dtype);
            ERR_add_error_data(2, "NID=", msgstr);
        }
        goto done;
        } break;
    }

#if 0
NOTE
/*
** Verify the signature on a block of data for which we already have
** the digest. The signature data is an RSA private key encrypted
** block of data formatted according to PKCS#1.
**  This function is deprecated. Use VFY_VerifyDigestDirect or 
**  VFY_VerifyDigestWithAlgorithmID instead.
** 	"dig" the digest
** 	"key" the public key to check the signature with
** 	"sig" the encrypted signature data
**	"sigAlg" specifies the signing algorithm to use.  This must match
**	    the key type.
**	"wincx" void pointer to the window context
**/
extern SECStatus VFY_VerifyDigest(SECItem *dig, SECKEYPublicKey *key,
				  SECItem *sig, SECOidTag sigAlg, void *wincx);
#endif

    rv = VFY_VerifyDigest(&digest, keyctx->pubkey, &sig, algid, wincx);
    nss_trace(ctx, "nss_rsa_verify() rv=%d\n", (int)rv);
    if (rv != SECSuccess) {
        int port_err = PORT_GetError();

        switch(port_err) {
        case SEC_ERROR_BAD_SIGNATURE: {
            NSSerr(NSS_F_RSA_VERIFY, NSS_R_BAD_SIGNATURE);
            } break;
        case SEC_ERROR_INVALID_ALGORITHM: {
            NSSerr(NSS_F_RSA_VERIFY, NSS_R_INVALID_ALGORITHM);
            } break;
        default: {
            int port_err_off = port_err - SEC_ERROR_BASE;

            nss_trace(ctx, "nss_rsa_verify() port_err/ofset=%d/%d\n", port_err, port_err_off);
            NSSerr(NSS_F_RSA_VERIFY, NSS_R_VERIFY_DIGEST_FAIL);
            {/*add extra error message data*/
                char msgstr[10];
                BIO_snprintf(msgstr, sizeof(msgstr), "%d", port_err_off);
                ERR_add_error_data(2, "PORT_ERROR_OFFSET=", msgstr);
            }
            } break;
        }
        goto done;
    }
}

    ret = 1;
done:
    nss_trace(ctx, "nss_rsa_verify() ret=%d\n", ret);
    return(ret);
}


static RSA_METHOD
nss_rsa_method = {
    "NSS PKCS#1 RSA method",
    NULL  /*same as RSA_PKCS1_SSLeay()->rsa_pub_enc */,
    NULL  /*same as RSA_PKCS1_SSLeay()->rsa_pub_dec */,
    nss_rsa_priv_enc,
    nss_rsa_priv_dec,
    NULL  /*same as RSA_PKCS1_SSLeay()->rsa_mod_exp */,
    NULL  /*same as RSA_PKCS1_SSLeay()->bn_mod_exp  */,
    nss_rsa_init,
    nss_rsa_finish,
    /* int flags; */
    RSA_FLAG_SIGN_VER |
#if 1
    RSA_FLAG_EXT_PKEY |
#endif
#if 0
    /* - don't check pub/private match ?*/
    RSA_METHOD_FLAG_NO_CHECK |
#endif
    0 ,
    NULL /* char *app_data; */,
    nss_rsa_sign,
    nss_rsa_verify,
    NULL /*rsa_keygen*/
};


static int/*bool*/
bind_nss_rsa_method(ENGINE *e) {
    const RSA_METHOD *rsa_method = RSA_PKCS1_SSLeay();

    CALL_TRACE("bind_nss_rsa_method() rsa_method=%p\n", rsa_method);
    nss_rsa_method.rsa_pub_enc = rsa_method->rsa_pub_enc;
    nss_rsa_method.rsa_pub_dec = rsa_method->rsa_pub_dec;
    nss_rsa_method.rsa_mod_exp = rsa_method->rsa_mod_exp;
    nss_rsa_method.bn_mod_exp  = rsa_method->bn_mod_exp;

    if (!ENGINE_set_RSA(e, &nss_rsa_method))
        return(0);
    return(1);
}
#endif /*ndef OPENSSL_NO_RSA*/
