/**
 * NSS Engine
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#if 1
#  define OPENSSL_EXPERIMENTAL_STORE
#endif
#include "e_nss_int.h"

#include <openssl/err.h>
#include "e_nss_err.c"

#include <openssl/engine.h>
#ifndef ENGINE_CMD_BASE
#  include "ENGINE_CMD_BASE is not defined"
#endif
#include <openssl/pem.h>
#ifndef OPENSSL_NO_STORE
#include <openssl/store.h>
#endif

#include <nspr/prinit.h>
#include <nss/nss.h>
#if 1
#  define NSS_VER_CHECK	((((NSS_VMAJOR<<8)|NSS_VMINOR)<<8)|NSS_VPATCH)
#  if NSS_VER_CHECK < 0x030903
#    include "NSS version < 3.9.3 is not supported"
#  endif
#endif
#include <nss/cert.h>
#include <nss/keyhi.h>
#include <nss/cryptohi.h>
#include <nss/secerr.h>


static inline void
CALL_TRACE(char *fmt, ...) {
#if 0
    va_list ap;
    va_start(ap, fmt);
    fputs("...TRACE ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
#endif
}


static void nss_vtrace(NSS_CTX *ctx, int level, char *fmt, va_list ap);


static inline void
nss_verbose(NSS_CTX *ctx, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    nss_vtrace(ctx, NSS_LOGLEVEL_VERBOSE, fmt, ap);
    va_end(ap);
}

static inline void
nss_debug(NSS_CTX *ctx, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    nss_vtrace(ctx, NSS_LOGLEVEL_DEBUG, fmt, ap);
    va_end(ap);
}

static inline void
nss_trace(NSS_CTX *ctx, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    nss_vtrace(ctx, NSS_LOGLEVEL_TRACE, fmt, ap);
    va_end(ap);
}


static inline NSS_CTX*
NSS_CTX_new(void) {
    NSS_CTX* ctx = OPENSSL_malloc(sizeof(NSS_CTX));

    if (ctx)
        memset(ctx, 0, sizeof(NSS_CTX));
    return(ctx);
}


static inline void
NSS_CTX_free(NSS_CTX *ctx) {
    if (ctx == NULL) return;

    if (ctx->config_dir) {
        OPENSSL_free((void*)ctx->config_dir);
        ctx->config_dir = NULL;
    }
    if (ctx->error_file) {
        OPENSSL_free((void*)ctx->error_file);
        ctx->error_file = NULL;
    }

    OPENSSL_free(ctx);
}


static inline NSS_KEYCTX*
NSS_KEYCTX_new(void) {
    NSS_KEYCTX *keyctx = OPENSSL_malloc(sizeof(NSS_KEYCTX));

    if (keyctx)
        memset(keyctx, 0, sizeof(NSS_KEYCTX));
    return(keyctx);
}


static inline void
NSS_KEYCTX_free(NSS_KEYCTX *keyctx) {
    if (keyctx == NULL) return;

    if (keyctx->pvtkey) {
        SECKEY_DestroyPrivateKey(keyctx->pvtkey);
        keyctx->pvtkey = NULL;
    }
    if (keyctx->pubkey) {
        SECKEY_DestroyPublicKey(keyctx->pubkey);
        keyctx->pubkey = NULL;
    }
    if (keyctx->cert) {
        CERT_DestroyCertificate(keyctx->cert);
        keyctx->cert = NULL;
    }
    OPENSSL_free(keyctx);
}


static int
CRYPTO_EX_NSS_CTX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    CALL_TRACE("CRYPTO_EX_NSS_CTX_new"
    "(parent=%p, ptr=%p, ad=%p, idx=%d, argl=%ld, argp=%p)\n",
      parent   , ptr   , ad   , idx   , argl    , argp);

    if (argp)
        CALL_TRACE("CRYPTO_EX_NSS_CTX_new()  argp=%s\n", argp);
    return(0);
}
static int
CRYPTO_EX_NSS_CTX_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d, int idx, long argl, void *argp) {
    CALL_TRACE("CRYPTO_EX_NSS_CTX_dup"
    "(to=%p, from=%p, from_d=%p, idx=%d, argl=%ld, argp=%p)\n",
      to   , from   , from_d   , idx   , argl    , argp);

    if (argp)
        CALL_TRACE("CRYPTO_EX_NSS_CTX_dup()  argp=%s\n", argp);
    return(0);
}
static void
CRYPTO_EX_NSS_CTX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    CALL_TRACE("CRYPTO_EX_NSS_CTX_free"
    "(parent=%p, ptr=%p, ad=%p, idx=%d, argl=%ld, argp=%p)\n",
      parent   , ptr   , ad   , idx   , argl    , argp);

    if (argp)
        CALL_TRACE("CRYPTO_EX_NSS_CTX_free()  argp=%s\n", argp);

    {
        ENGINE *e = (ENGINE *)(parent);
        CALL_TRACE("CRYPTO_EX_NSS_CTX_free()  id=%s\n", ENGINE_get_id(e));
        CALL_TRACE("CRYPTO_EX_NSS_CTX_free()  name=%s\n", ENGINE_get_name(e));
    }
}


/*
 * Constants used when creating the context extra data
 */
static int nss_eng_ctx_index = -1;
static int nss_rsa_ctx_index = -1;


/*
 * Constants used when creating the ENGINE
 */

static const char *nss_engine_id = "e_nss";
static const char *nss_engine_name = NSS_ENG_NAME " (" NSS_ENG_VERSION ")";


#include "e_nss_cmd.c"
#include "e_nss_ui.c"
#include "e_nss_key.c"
#include "e_nss_rsa.c"
#include "e_nss_store.c"


/*
 * Functions to handle the engine
 */

static int/*bool*/
nss_init_eng_ctx(ENGINE *e) {
    CALL_TRACE("nss_init_eng_ctx() e=%p, nss_eng_ctx_index=%d\n", e, nss_eng_ctx_index);

    if (nss_eng_ctx_index >= 0) return(1);

    /*NOTE crash if nss_init_eng_ctx() called from bind_nss*/
#if 1
    nss_eng_ctx_index = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, NULL);
#else
    /*NOTE crash if CRYPTO_EX_NSS_CTX_free is set*/
    nss_eng_ctx_index = ENGINE_get_ex_new_index(0, "Test by Roumen", CRYPTO_EX_NSS_CTX_new, CRYPTO_EX_NSS_CTX_dup, CRYPTO_EX_NSS_CTX_free);
#endif

    CALL_TRACE("nss_init_eng_ctx() NEW nss_eng_ctx_index=%d\n", nss_eng_ctx_index);
    if (nss_eng_ctx_index < 0) return(0);

    {
        NSS_CTX *ctx = NSS_CTX_new();

        CALL_TRACE("nss_init_eng_ctx() ctx=%p\n", ctx);
        if (ctx == NULL) {
            return(0);
        }
        ENGINE_set_ex_data(e, nss_eng_ctx_index, ctx);
    }
    return(1);
}


static int/*bool*/
nss_init(ENGINE *e) {
    int ret = 0;

    CALL_TRACE("nss_init() e=%p\n", e);
    /* ensure engine context index */
    if (!nss_init_eng_ctx(e)) {
        NSSerr(NSS_F_INIT, NSS_R_ENG_CTX_INDEX);
        goto done;
    }

    /* ensure RSA context index */
    nss_rsa_ctx_index = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    CALL_TRACE("nss_init() nss_rsa_ctx_index=%d\n", nss_rsa_ctx_index);
    if (nss_rsa_ctx_index < 0) {
        NSSerr(NSS_F_INIT, NSS_R_RSA_CTX_INDEX);
        goto done;
    }

    /* ensure that nss globals are set up */
#if 1
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
#endif
    PK11_SetPasswordFunc(nss_pass_func);
/*
 * Not yet (see comment in pk11wrap/pk11auth.c): "... we simply tell the
 * server code that it should now verify the clients password and tell us
 * the results."
    PK11_SetVerifyPasswordFunc(...);
*/

    ret = 1;
done:
    CALL_TRACE("nss_init() %s^\n", (ret ? "ok": ""));
    return(ret);
}


static int
nss_finish(ENGINE *e) {
    CALL_TRACE("nss_finish()\n");

    if (NSS_IsInitialized()) {
        SECStatus  rv;

        rv = NSS_Shutdown();
        if (rv != SECSuccess) {
            NSSerr(NSS_F_FINISH, NSS_R_SHUTDOWN_FAIL);
        }
    }

    if (nss_eng_ctx_index >= 0) {
        NSS_CTX *ctx;

        ctx = ENGINE_get_ex_data(e, nss_eng_ctx_index);
        ENGINE_set_ex_data(e, nss_eng_ctx_index, NULL);
        nss_eng_ctx_index = -1;
        NSS_CTX_free(ctx);
    }

    return(1);
}


static int
nss_destroy(ENGINE *e) {
    CALL_TRACE("nss_destroy()\n");

#ifndef OPENSSL_NO_STORE
{
    STORE_METHOD *sm = (STORE_METHOD*) ENGINE_get_STORE(e);
    if (sm) {
        ENGINE_set_STORE(e, NULL);
        STORE_destroy_method(sm);
    }
}
#endif

    ERR_unload_NSS_strings();
    return(1);
}


static int/*bool*/
bind_nss(ENGINE *e) {
    CALL_TRACE("bind_nss() e=%p\n", e);

    if (!ENGINE_set_id(e, nss_engine_id)
    ||  !ENGINE_set_name(e, nss_engine_name)
    ||  !ENGINE_set_cmd_defns(e, nss_cmd_defns)
    ||  !ENGINE_set_ctrl_function(e, nss_ctrl)
    ||  !ENGINE_set_init_function(e, nss_init)
    ||  !ENGINE_set_finish_function(e, nss_finish)
    ||  !ENGINE_set_destroy_function(e, nss_destroy)
    ||  !ENGINE_set_load_privkey_function(e, nss_load_privkey)
    ||  !ENGINE_set_load_pubkey_function(e, nss_load_pubkey)
  /*||  !ENGINE_set_ciphers(e, nss_ciphers)*/
  /*||  !ENGINE_set_digests(e, nss_digests)*/
    )
        return(0);

#ifndef OPENSSL_NO_RSA
    if (!bind_nss_rsa_method(e))
        return(0);
#endif

#ifndef OPENSSL_NO_STORE
    if (!bind_nss_store_method(e))
        return(0);
#endif

#if 0
CRASH !?!?
    if (!nss_init_eng_ctx(e))
        return(0);
#endif

    /* ensure the nss error handling is set up */
    ERR_load_NSS_strings();

    return(1);
}


#if OPENSSL_VERSION_NUMBER >= 0x00908000L

/*now definitions are in 0.9.8 engine style*/

#else

/*set dynamic/static support defines in 0.9.8 style*/
#undef OPENSSL_NO_DYNAMIC_ENGINE
#undef OPENSSL_NO_STATIC_ENGINE

#ifdef ENGINE_DYNAMIC_SUPPORT
#  define OPENSSL_NO_STATIC_ENGINE
#else
#  define OPENSSL_NO_DYNAMIC_ENGINE
#endif

#endif /*OPENSSL_VERSION_NUMBER < 0x00908000L*/


/*TODO libtool and openssl integration - has to be in configure*/
#ifdef PIC
#  ifdef OPENSSL_NO_DYNAMIC_ENGINE
#    include "openssl require dynamic engine"
#  endif
#else
#  ifdef OPENSSL_NO_STATIC_ENGINE
#    include "openssl require static engine"
#  endif
#endif


#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int/*bool*/
bind_helper(ENGINE *e, const char *id) {

    CALL_TRACE("bind_helper(): e=%p, id=%s\n", e, (id ? id: "<none>"));

    if (id && (strcmp(id, nss_engine_id) != 0))
        return(0);
    return(bind_nss(e));
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif /*ndef OPENSSL_NO_STATIC_ENGINE*/


#ifndef OPENSSL_NO_STATIC_ENGINE
static ENGINE *
engine_nss(void) {
    ENGINE *e;

    CALL_TRACE("engine_nss()\n");

    e = ENGINE_new();
    if (!e)
        return(NULL);
    if (!bind_nss(e)) {
        ENGINE_free(e);
        return(NULL);
    }
    return(e);
}


extern void ENGINE_load_nss(void);
void
ENGINE_load_nss(void) {
    /* copied from eng_[openssl|dyn].c */
    ENGINE *e;

    CALL_TRACE("ENGINE_load_nss()\n");

    e = engine_nss();
    if (!e) return;
    ENGINE_add(e);
    ENGINE_free(e);
    ERR_clear_error();
}
#endif /*ndef OPENSSL_NO_DYNAMIC_ENGINE*/


/* ================================================================= */

static void
nss_vtrace(NSS_CTX *ctx, int level, char *fmt, va_list ap) {
    BIO *err;

    if (ctx == NULL) return;
    if (ctx->debug_level < level) return;

    if (ctx->error_file)
        err = BIO_new_file(ctx->error_file, "a+");
    else
        err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!err) return;

    switch (level) {
    case NSS_LOGLEVEL_VERBOSE: BIO_puts(err, "INFO["); break;
    case NSS_LOGLEVEL_DEBUG  : BIO_puts(err, "DEBUG["  ); break;
    case NSS_LOGLEVEL_TRACE  : BIO_puts(err, "TRACE["  ); break;
    }
    BIO_puts(err, nss_engine_id);
    BIO_puts(err, "] ");

    BIO_vprintf(err, fmt, ap);
    BIO_free(err);
}
