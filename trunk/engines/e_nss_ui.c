/**
 * NSS Engine - user interface
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

#if 0
#  define USE_OPENSSL_VERIFY_PROMPT
#endif
static char*
nss_openssl_pass_func(PK11SlotInfo *slot, UI_METHOD *ui_method, void *callback_data) {
    char *ret = NULL;
    UI *ui = NULL;

    CALL_TRACE("nss_openssl_pass_func() PK11_GetSlotName ()='%s'\n", PK11_GetSlotName (slot));
    CALL_TRACE("nss_openssl_pass_func() PK11_GetTokenName()='%s'\n", PK11_GetTokenName(slot));
    CALL_TRACE("nss_openssl_pass_func() PK11_GetMinimumPwdLength()=%d\n", PK11_GetMinimumPwdLength(slot));
    CALL_TRACE("nss_openssl_pass_func() NSS_UI ui_method=%p, callback_data=%p\n", ui_method, callback_data);

    if (ui_method == NULL) goto done;

    ui = UI_new_method(ui_method);
    if (ui == NULL) goto done;

    if (callback_data)
        UI_add_user_data(ui, callback_data);

    UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

    { /*promt for password */
        int   ok;
        char *prompt;

        int   ui_flags = UI_INPUT_FLAG_DEFAULT_PWD;
        int   min_len = PK11_GetMinimumPwdLength(slot);
        int   max_len = 100;
        char *buf1;
    #ifdef USE_OPENSSL_VERIFY_PROMPT
        char *buf2;
    #endif

        buf1 = OPENSSL_malloc(max_len);
    #ifdef USE_OPENSSL_VERIFY_PROMPT
        buf2 = OPENSSL_malloc(max_len);
    #endif

        prompt = UI_construct_prompt(ui, "pass phrase", PK11_GetTokenName(slot));
        if (prompt == NULL) goto passdone;

        CALL_TRACE("nss_openssl_pass_func() prompt = %s\n", prompt);

    #if 0 /* not yet */
        UI_add_info_string(ui, PK11_GetSlotName (slot));
    #endif

        ok = UI_add_input_string(ui, prompt, ui_flags, buf1, min_len, max_len - 1);
        if (ok < 0) goto passdone;

    #ifdef USE_OPENSSL_VERIFY_PROMPT
        ok = UI_add_verify_string(ui, prompt, ui_flags, buf2, min_len, max_len - 1, buf1);
        if (ok < 0) goto passdone;
    #endif

        do {
            ok = UI_process(ui);
        } while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

        ret = PL_strdup(buf1);

passdone:
        CALL_TRACE("nss_openssl_pass_func() buf1 = %s\n", buf1);
    #ifdef USE_OPENSSL_VERIFY_PROMPT
        CALL_TRACE("nss_openssl_pass_func() buf2 = %s\n", buf2);
    #endif
        CALL_TRACE("nss_openssl_pass_func() UI result[0] = %s\n", UI_get0_result(ui, 0));
    #ifdef USE_OPENSSL_VERIFY_PROMPT
        CALL_TRACE("nss_openssl_pass_func() UI result[1] = %s\n", UI_get0_result(ui, 1));
    #endif
        /* DO NOT READ MORE as ui_lib.c raise error !
        nss_trace(ctx, "nss_openssl_pass_func() UI result[2] = %s\n", UI_get0_result(ui, 2)); */

        if (buf1) {
            OPENSSL_cleanse(buf1, max_len);
            OPENSSL_free(buf1);
        }
    #ifdef USE_OPENSSL_VERIFY_PROMPT
        if (buf2) {
            OPENSSL_cleanse(buf2, max_len);
            OPENSSL_free(buf2);
        }
    #endif
        if (prompt)
            OPENSSL_free(prompt);
    }

done:
    if (ui)
        UI_free(ui);
    return(ret);
}
#ifdef USE_OPENSSL_VERIFY_PROMPT
# undef USE_OPENSSL_VERIFY_PROMPT
#endif


static char*
nss_pass_func(PK11SlotInfo *slot, PRBool retry, void *arg) {
    NSS_UI *wincx = (NSS_UI*)arg;

    CALL_TRACE("nss_pass_func(slot=%p, retry=%d, arg=%p) CALLED\n", slot, retry, arg);

    if (arg == NULL) return(NULL);
    if (retry) return(NULL);

    return(nss_openssl_pass_func(slot, wincx->ui_method, wincx->callback_data));
}
