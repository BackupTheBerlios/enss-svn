/**
 * NSS Engine - errors
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

#define NSSerr(f,r)   ERR_NSS_error( (f), (r), __FILE__, __LINE__)

/* Functions */
#define NSS_F_INIT					 100
#define NSS_F_CTRL					 101
#define NSS_F_FINISH					 102
#define NSS_F_CMD_CONFIG_DIR				 103
#define NSS_F_CMD_LIST_CERT				 104
#define NSS_F_LOAD_KEY					 110
#define NSS_F_RSA_INIT					 120
#define NSS_F_RSA_FINISH				 121
#define NSS_F_RSA_PRIV_DEC				 122
#define NSS_F_RSA_PRIV_ENC				 123
#define NSS_F_RSA_SIGN					 124
#define NSS_F_RSA_VERIFY				 125
#define NSS_F_DSA_INIT					 130
#define NSS_F_DSA_FINISH				 131

/* Reasons */
#define NSS_R_INSUFFICIENT_MEMORY			 100
#define NSS_R_ENG_CTX_INDEX				 101
#define NSS_R_RSA_CTX_INDEX				 102
#define NSS_R_DSA_CTX_INDEX				 103
#define NSS_R_SHUTDOWN_FAIL				 109

#define NSS_R_INVALID_ARGUMENT				 110
#define NSS_R_ENGINE_NOT_INITIALIZED			 111
#define NSS_R_DB_IS_NOT_INITIALIZED			 112
#define NSS_R_CANNOT_SETUP_CONFIG_DIR			 113
#define NSS_R_CONFIG_DIR_IS_SET				 114

#define NSS_R_NOT_SUPPORTED				 120
#define NSS_R_INVALID_ALGORITHM				 121
#define NSS_R_UNSUPPORTED_KEYTYPE			 122
#define NSS_R_UNSUPPORTED_NID				 123
#define NSS_R_UNSUPPORTED_PADDING			 124

#define NSS_R_MISSING_KEY_CONTEXT			 130
#define NSS_R_MISSING_CERT				 131
#define NSS_R_MISSING_PUBKEY				 132
#define NSS_R_MISSING_PVTKEY				 133
#define NSS_R_DERENCODE_PUBKEY				 134
#define NSS_R_DERENCODE_PUBKEYBUF			 135

#define NSS_R_BAD_SIGNATURE				 140
#define NSS_R_DECRYPT_FAIL				 141
#define NSS_R_SIGN_DIGEST_FAIL				 142
#define NSS_R_VERIFY_DIGEST_FAIL			 143


#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func)		ERR_PACK(0, func, 0)

static ERR_STRING_DATA
NSS_str_functs[] = {
    { ERR_FUNC(NSS_F_INIT)		, "INIT" },
    { ERR_FUNC(NSS_F_CTRL)		, "CTRL" },
    { ERR_FUNC(NSS_F_FINISH)		, "FINISH" },
    { ERR_FUNC(NSS_F_CMD_CONFIG_DIR)	, "CMD_CONFIG_DIR" },
    { ERR_FUNC(NSS_F_CMD_LIST_CERT)	, "CMD_LIST_CERT" },
    { ERR_FUNC(NSS_F_LOAD_KEY)		, "LOAD_KEY" },
    { ERR_FUNC(NSS_F_RSA_INIT)		, "RSA_INIT" },
    { ERR_FUNC(NSS_F_RSA_FINISH)	, "RSA_FINISH" },
    { ERR_FUNC(NSS_F_RSA_PRIV_DEC)	, "RSA_PRIV_DEC" },
    { ERR_FUNC(NSS_F_RSA_PRIV_ENC)	, "RSA_PRIV_ENC" },
    { ERR_FUNC(NSS_F_RSA_SIGN)		, "RSA_SIGN" },
    { ERR_FUNC(NSS_F_RSA_VERIFY)	, "RSA_VERIFY" },
    { ERR_FUNC(NSS_F_DSA_INIT)		, "DSA_INIT" },
    { ERR_FUNC(NSS_F_DSA_FINISH)	, "DSA_FINISH" },
    {0,  NULL}
};


#define ERR_REASON(reason)	ERR_PACK(0, 0, reason)

static ERR_STRING_DATA
NSS_str_reasons[] = {
    { ERR_REASON(NSS_R_INSUFFICIENT_MEMORY)	, "Insufficient memory" },
    { ERR_REASON(NSS_R_ENG_CTX_INDEX)		, "Engine context index" },
    { ERR_REASON(NSS_R_RSA_CTX_INDEX)		, "RSA context index" },
    { ERR_REASON(NSS_R_DSA_CTX_INDEX)		, "DSA context index" },
    { ERR_REASON(NSS_R_SHUTDOWN_FAIL)		, "Shutdown fail" },

    { ERR_REASON(NSS_R_INVALID_ARGUMENT)	, "Invalid argument" },
    { ERR_REASON(NSS_R_ENGINE_NOT_INITIALIZED)	, "Engine not initialized" },
    { ERR_REASON(NSS_R_DB_IS_NOT_INITIALIZED)	, "DB is not initialized" },
    { ERR_REASON(NSS_R_CANNOT_SETUP_CONFIG_DIR)	, "Cannot setup config dir" },
    { ERR_REASON(NSS_R_CONFIG_DIR_IS_SET)	, "Config dir is set" },

    { ERR_REASON(NSS_R_NOT_SUPPORTED)		, "Not supported" },
    { ERR_REASON(NSS_R_INVALID_ALGORITHM)	, "Invalid algorithm" },
    { ERR_REASON(NSS_R_UNSUPPORTED_KEYTYPE)	, "Unsupported key type" },
    { ERR_REASON(NSS_R_UNSUPPORTED_NID)		, "Unsupported NID" },
    { ERR_REASON(NSS_R_UNSUPPORTED_PADDING)	, "Unsupported padding" },

    { ERR_REASON(NSS_R_MISSING_KEY_CONTEXT)	, "Missing key context" },
    { ERR_REASON(NSS_R_MISSING_CERT)		, "Missing certificate" },
    { ERR_REASON(NSS_R_MISSING_PUBKEY)		, "Missing public key" },
    { ERR_REASON(NSS_R_MISSING_PVTKEY)		, "Missing private key" },
    { ERR_REASON(NSS_R_DERENCODE_PUBKEY)	, "Derencode pubkey" },
    { ERR_REASON(NSS_R_DERENCODE_PUBKEYBUF)	, "Derencode pubkeybuf" },

    { ERR_REASON(NSS_R_BAD_SIGNATURE)		, "Bad Signature" },
    { ERR_REASON(NSS_R_DECRYPT_FAIL)		, "Decrypt fail" },
    { ERR_REASON(NSS_R_SIGN_DIGEST_FAIL)	, "Sign digest fail" },
    { ERR_REASON(NSS_R_VERIFY_DIGEST_FAIL)	, "Verify digest fail" },
    { 0, NULL}
};

#endif /*ndef OPENSSL_NO_ERR*/


static ERR_STRING_DATA
NSS_lib_name[] = {
   {0, NSS_LIB_NAME},
   {0, NULL}
};


static int NSS_lib_error_code = 0;
static int NSS_error_init = 1;

static void
ERR_load_NSS_strings(void) {
    if (NSS_lib_error_code == 0)
        NSS_lib_error_code = ERR_get_next_error_library();

    if (NSS_error_init) return;

    NSS_error_init = 0;
#ifndef OPENSSL_NO_ERR
    ERR_load_strings(NSS_lib_error_code, NSS_str_functs);
    ERR_load_strings(NSS_lib_error_code, NSS_str_reasons);
#endif /*ndef OPENSSL_NO_ERR*/

    NSS_lib_name->error = ERR_PACK(NSS_lib_error_code, 0, 0);
    ERR_load_strings(0, NSS_lib_name);
}

static void
ERR_unload_NSS_strings(void) {
    if (NSS_error_init == 0) return;

#ifndef OPENSSL_NO_ERR
    ERR_unload_strings(NSS_lib_error_code, NSS_str_functs);
    ERR_unload_strings(NSS_lib_error_code, NSS_str_reasons);
#endif /*ndef OPENSSL_NO_ERR*/

    ERR_unload_strings(0, NSS_lib_name);
    NSS_error_init = 1;
}

static void
ERR_NSS_error(int function, int reason, const char *file, int line) {
    if (NSS_lib_error_code == 0)
        NSS_lib_error_code = ERR_get_next_error_library();

    ERR_PUT_error(NSS_lib_error_code, function, reason, file, line);
}
