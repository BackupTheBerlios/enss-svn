/**
 * NSS Engine - controll commands
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

static int/*bool*/
nss_cmd_nss_config_dir(NSS_CTX *ctx, const char *s) {
    int        ret = 0;
    SECStatus  rv;

    CALL_TRACE("nss_cmd_nss_config_dir...\n");

    if (ctx == NULL) {
        NSSerr(NSS_F_CMD_CONFIG_DIR, NSS_R_INVALID_ARGUMENT);
        goto done;
    }
    if (s == NULL) {
        NSSerr(NSS_F_CMD_CONFIG_DIR, NSS_R_INVALID_ARGUMENT);
        goto done;
    }

    nss_trace(ctx, "nss_cmd_nss_config_dir('%s')\n", s);
    if (ctx->config_dir != NULL) {
#if 0 /*TODO: once set we may not change until restart of engine*/
        OPENSSL_free(nss_config_dir);
        nss_config_dir = NULL;
#endif
        NSSerr(NSS_F_CMD_CONFIG_DIR, NSS_R_CONFIG_DIR_IS_SET);
        goto done;
    }

    ctx->config_dir = BUF_strdup(s);
    if (ctx->config_dir == NULL) {
        NSSerr(NSS_F_CMD_CONFIG_DIR, NSS_R_INSUFFICIENT_MEMORY);
        goto done;
    }

    rv = NSS_Init(ctx->config_dir);
    if (rv != SECSuccess) {
        NSSerr(NSS_F_CMD_CONFIG_DIR, NSS_R_CANNOT_SETUP_CONFIG_DIR);
        goto done;
    }

#if 0
# SSL_OptionSetDefault. Changes default values for all subsequently opened sockets as long as the application is running (compare with SSL_SetURL which only configures the socket that is currently open). This function must be called once for each default value that needs to be changed. Optional.
# NSS_SetDomesticPolicy, NSS_SetExportPolicy, NSS_SetFrancePolicy, or SSL_CipherPolicySet. These functions tell the library which cipher suites are permitted by policy (for example, to comply with export restrictions). Cipher suites disabled by policy cannot be enabled by user preference. One of these functions must be called before any cryptographic operations can be performed with NSS.
# SSL_CipherPrefSetDefault. Enables all ciphers chosen by user preference. Optional.
#endif

    ret = 1;
done:
    return(ret);
}


static int
nss_cmd_list_cert(NSS_CTX *ctx, long i) {
    int ret = 0;
    BIO  *out = NULL;
    void *wincx = NULL;

    CERTCertList     *list;
    CERTCertListNode *node;
    PK11CertListType  type;

    CALL_TRACE("nss_cmd_list_cert: %ld\n", i);

    if (ctx == NULL) {
        NSSerr(NSS_F_CMD_LIST_CERT, NSS_R_INVALID_ARGUMENT);
        goto done;
    }
    if (!NSS_IsInitialized()) {
        NSSerr(NSS_F_CMD_LIST_CERT, NSS_R_DB_IS_NOT_INITIALIZED);
        goto done;
    }

#if 0
softoken/secmodt.h:     PK11CertListUnique = 0,     /* get one instance of all certs */
softoken/secmodt.h:     PK11CertListUser = 1,       /* get all instances of user certs */
softoken/secmodt.h:     PK11CertListRootUnique = 2, /* get one instance of CA certs without a private key. */
softoken/secmodt.h:     PK11CertListCA = 3,         /* get all instances of CA certs */
softoken/secmodt.h:     PK11CertListCAUnique = 4,   /* get one instance of CA certs */
softoken/secmodt.h:     PK11CertListUserUnique = 5, /* get one instance of user certs */
softoken/secmodt.h:     PK11CertListAll = 6         /* get all instances of all certs */
#endif
    switch (i) {
    case 1: type = PK11CertListUser; break;
    case 2: type = PK11CertListCA  ; break;
    case 3: type = PK11CertListAll ; break;
    default:
        goto done;
        break;
    }

    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    list = PK11_ListCerts(type, wincx);
    for (node = CERT_LIST_HEAD(list);
         !CERT_LIST_END(node, list);
         node = CERT_LIST_NEXT(node)
    ) {
        CERTCertificate *cert = node->cert;

        BIO_printf(out, "nickname='%s'\n"      , cert->nickname);
        BIO_printf(out, "  subject_name='%s'\n", cert->subjectName);
        BIO_printf(out, "  email_addr  ='%s'\n", cert->emailAddr);
    }
    CERT_DestroyCertList(list);

    ret = 1;
done:
    if (out) BIO_free(out);
    return(ret);
}


/*convert CERTCertificate to X509*/
static X509*
X509_from_CERTCertificate(const CERTCertificate *cert) {
    X509 *x509 = NULL;
    BIO *mbio;

    mbio = BIO_new_mem_buf(cert->derCert.data, cert->derCert.len);
    if (mbio == NULL) return(NULL);

    x509 = d2i_X509_bio(mbio, NULL);

    BIO_free(mbio);
    return(x509);
}


static X509*
nss_get_cert(NSS_CTX *ctx, const char *s) {
    X509 *x509 = NULL;
    CERTCertificate *cert = NULL;

    CALL_TRACE("nss_get_cert...\n");

    if (ctx == NULL) {
        NSSerr(NSS_F_GET_CERT, NSS_R_INVALID_ARGUMENT);
        goto done;
    }
    if (!NSS_IsInitialized()) {
        NSSerr(NSS_F_GET_CERT, NSS_R_DB_IS_NOT_INITIALIZED);
        goto done;
    }

    nss_debug(ctx, "search certificate '%s'", s);
    cert = PK11_FindCertFromNickname(s, NULL);
    nss_trace(ctx, "found certificate mem='%p'", cert);

    if (cert == NULL) goto done;

    x509 = X509_from_CERTCertificate(cert);

done:
    if (cert) CERT_DestroyCertificate(cert);

    nss_debug(ctx, "certificate %s", (x509 ? "found": "not found"));
    return(x509);
}


static int
nss_cmd_print_cert(NSS_CTX *ctx, const char *s) {
    int ret = 0;
    X509 *x509 = NULL;

    x509 = nss_get_cert(ctx, s);
    if (x509 == NULL) goto done;

    {/*print certificate*/
        const int nmflag = ((XN_FLAG_ONELINE & \
                             ~ASN1_STRFLGS_ESC_MSB & \
                             ~XN_FLAG_SPC_EQ & \
                             ~XN_FLAG_SEP_MASK) | \
                             XN_FLAG_SEP_COMMA_PLUS);
        const int certflag = 0;
        BIO *out;

        out = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (out == NULL) goto done;

        X509_print_ex(out, x509, nmflag, certflag);
        PEM_write_bio_X509(out, x509);
        BIO_free(out);
    }

    ret = 1;
done:
    if (x509) X509_free(x509);
    return(ret);
}


static int
nss_cmd_load_cert(NSS_CTX *ctx, void *p) {
    struct {
        const char *nickname;
        X509 *x509;
    } *param = p;

    param->x509 = nss_get_cert(ctx, param->nickname);

    return(param->x509 ? 1 : 0);
}


static int
nss_cmd_evp_cert(NSS_CTX *ctx, void *p) {
    NSS_KEYCTX *keyctx = NULL;
    struct {
        EVP_PKEY *pkey;
        X509 *x509;
    } *param = p;

    switch (param->pkey->type) {
    case EVP_PKEY_RSA: {
        RSA *pkey_rsa = EVP_PKEY_get1_RSA(param->pkey);
        keyctx = RSA_get_ex_data(pkey_rsa, nss_rsa_ctx_index);
        RSA_free(pkey_rsa);
        } break;
    case EVP_PKEY_DSA: {
        DSA *pkey_dsa = EVP_PKEY_get1_DSA(param->pkey);
        keyctx = DSA_get_ex_data(pkey_dsa, nss_dsa_ctx_index);
        DSA_free(pkey_dsa);
        } break;
    default: {
        NSSerr(NSS_F_CMD_EVP_CERT, NSS_R_UNSUPPORTED_KEYTYPE);
        { /* add extra error message data */
            char msgstr[10];
            BIO_snprintf(msgstr, sizeof(msgstr), "%d", param->pkey->type);
            ERR_add_error_data(2, "KEYTYPE=", msgstr);
        }
        } break;
    }

    param->x509 = X509_from_CERTCertificate(keyctx->cert);

    return(param->x509 ? 1 : 0);
}


#if 0
/* NOTE SO_PATH is designed to load vendor shared library
 * Not implemented yet.
 */
#define CMD_SO_PATH              (ENGINE_CMD_BASE)
#endif
#define E_NSS_CMD_BASE           (ENGINE_CMD_BASE+10)
#define E_NSS_CMD_USER           (ENGINE_CMD_BASE+20)

#define E_NSS_CMD_CONFIG_DIR     (E_NSS_CMD_BASE)
#define E_NSS_CMD_DEBUG_LEVEL    (E_NSS_CMD_BASE+1)
#define E_NSS_CMD_ERROR_FILE     (E_NSS_CMD_BASE+2)

#define E_NSS_CMD_LIST_CERTS     (E_NSS_CMD_USER+10)
#define E_NSS_CMD_PRINT_CERT     (E_NSS_CMD_USER+11)
#define E_NSS_CMD_LOAD_CERT      (E_NSS_CMD_USER+12)
#define E_NSS_CMD_EVP_CERT       (E_NSS_CMD_USER+13)

static const ENGINE_CMD_DEFN nss_cmd_defns[] = {
#ifdef CMD_SO_PATH
    {CMD_SO_PATH,
     "SO_PATH",
     "Specifies the path to the 'nss' shared library",
     ENGINE_CMD_FLAG_STRING},
#endif
    {E_NSS_CMD_CONFIG_DIR,
     "CONFIG_DIR",
     "Specifies the nss config directory",
     ENGINE_CMD_FLAG_STRING},
    {E_NSS_CMD_DEBUG_LEVEL,
     "DEBUG",
     "debug level (1=info, 2=debug, 3=trace)",
     ENGINE_CMD_FLAG_NUMERIC},
    {E_NSS_CMD_ERROR_FILE,
     "ERROR_OUTPUT",
     "Specifies the name of output file for debug (stderr by default)",
     ENGINE_CMD_FLAG_STRING},
    {E_NSS_CMD_LIST_CERTS,
     "LIST_CERTS",
     "List certificates (1=User, 2=CA, 3=All)",
     ENGINE_CMD_FLAG_NUMERIC},
    {E_NSS_CMD_PRINT_CERT,
     "PRINT_CERT",
     "Search and print certificate by specified nickname",
     ENGINE_CMD_FLAG_STRING},
    {E_NSS_CMD_LOAD_CERT,
     "LOAD_CERT_CTRL",
     "Return certificate found by specified nickname",
     ENGINE_CMD_FLAG_INTERNAL},
    {E_NSS_CMD_EVP_CERT,
     "LOAD_CERT_EVP",
     "Return certificate for specified EVP KEY",
     ENGINE_CMD_FLAG_INTERNAL},
    {0, NULL, NULL, 0}
};


static int/*bool*/
nss_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)()) {
    int ret = 0;
    NSS_CTX *ctx;

    CALL_TRACE("nss_ctrl() cmd=%d\n", cmd);

/* Put commands that do not require initialisation here*/
    switch (cmd) {
#ifdef CMD_SO_PATH
    case CMD_SO_PATH: {
        /* not implemented */;
        goto done;
        } break;
#endif
    }

/* Put commands that require initialisation here */
    if (nss_eng_ctx_index < 0) {
        NSSerr(NSS_F_CTRL, NSS_R_ENGINE_NOT_INITIALIZED);
        return(ret);
    }
    ctx = ENGINE_get_ex_data(e, nss_eng_ctx_index);

    switch (cmd) {
    case E_NSS_CMD_CONFIG_DIR: {
        ret = nss_cmd_nss_config_dir(ctx, (char*) p);
        } break;
    case E_NSS_CMD_DEBUG_LEVEL: {
        if (0 <= i && i <= NSS_LOGLEVEL_LAST) {
            ctx->debug_level = (int) i;
            ret = 1;
        }
        } break;
    case E_NSS_CMD_ERROR_FILE: {
        if (ctx->error_file != NULL)
            OPENSSL_free((void*)ctx->error_file);
        ctx->error_file = BUF_strdup(p);
        ret = 1;
        } break;
    case E_NSS_CMD_LIST_CERTS: {
        ret = nss_cmd_list_cert(ctx, i);
        } break;
    case E_NSS_CMD_PRINT_CERT: {
        ret = nss_cmd_print_cert(ctx, (char*) p);
        } break;
    case E_NSS_CMD_LOAD_CERT: {
        ret = nss_cmd_load_cert(ctx, p);
        } break;
    case E_NSS_CMD_EVP_CERT: {
        ret = nss_cmd_evp_cert(ctx, p);
        } break;
    default: {
        nss_trace(ctx, "nss_ctrl() <UNKNOWN=%d>\n", cmd);
        goto done;
        } break;
    }

done:
    return(ret);
}
