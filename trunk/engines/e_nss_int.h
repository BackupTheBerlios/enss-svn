#ifndef HEADER_NSS_INT_H
#define HEADER_NSS_INT_H
/**
 * NSS Engine - internals
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

#include <nss/pk11pub.h>
#include <openssl/ossl_typ.h>


#ifdef  __cplusplus
extern "C" {
#endif


#define NSS_LIB_NAME		"E_NSS"
#define NSS_ENG_NAME		"NSS engine support"
#define NSS_ENG_VERSION		"0.2.1"


#define NSS_LOGLEVEL_VERBOSE	1
#define NSS_LOGLEVEL_DEBUG	2
#define NSS_LOGLEVEL_TRACE	3
#define NSS_LOGLEVEL_LAST	NSS_LOGLEVEL_TRACE


struct NSS_CTX_s {
    /* setup */
    char             *config_dir;

    /* for internal use */
    int               debug_level;
    const char       *error_file;
};

typedef struct NSS_CTX_s NSS_CTX;


struct NSS_KEYCTX_s {
    CERTCertificate   *cert;
    SECKEYPublicKey   *pubkey;
    SECKEYPrivateKey  *pvtkey;
};

typedef struct NSS_KEYCTX_s NSS_KEYCTX;


struct NSS_UI_s {
    UI_METHOD *ui_method;
    void      *callback_data;
};

typedef struct NSS_UI_s NSS_UI;


#define UNUSED(a)       (void)a

#ifdef  __cplusplus
}
#endif
#endif /*ndef HEADER_NSS_INT_H*/
