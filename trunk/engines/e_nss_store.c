/**
 * NSS Engine - STORE functions
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2011 Roumen Petrov
 */

#ifndef OPENSSL_NO_STORE
static int
nss_store_init(STORE* store) {
   CALL_TRACE("nss_store_init...\n");
   return(0);
}

static int
nss_store_ctrl(STORE *store, int cmd, long l, void *p, void (*f)(void)) {
   CALL_TRACE("nss_store_ctrl...\n");
   return(0);
}

static STORE_OBJECT*
nss_store_get_object(STORE *store, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]) {
   CALL_TRACE("nss_store_get_object...\n");
   return(NULL);
}


/*
 * NSS STORE method
 *
 * NOTE allocated dynamicaly
 */

static int/*bool*/
bind_nss_store_method(ENGINE *e) {
    STORE_METHOD *sm;

    CALL_TRACE("bind_nss_store_method() e=%p\n", e);

    sm = STORE_create_method("NSS store");
    if(!sm)
        return(0);

    if (!STORE_method_set_initialise_function(sm, nss_store_init)
    ||  !STORE_method_set_get_function(sm, nss_store_get_object)
    ||  !STORE_method_set_ctrl_function(sm, nss_store_ctrl)
    )
        return(0);
#if 0
int STORE_method_set_cleanup_function(STORE_METHOD *sm, STORE_CLEANUP_FUNC_PTR clean_f);
int STORE_method_set_generate_function(STORE_METHOD *sm, STORE_GENERATE_OBJECT_FUNC_PTR generate_f);
int STORE_method_set_store_function(STORE_METHOD *sm, STORE_STORE_OBJECT_FUNC_PTR store_f);
int STORE_method_set_modify_function(STORE_METHOD *sm, STORE_MODIFY_OBJECT_FUNC_PTR store_f);
int STORE_method_set_revoke_function(STORE_METHOD *sm, STORE_HANDLE_OBJECT_FUNC_PTR revoke_f);
int STORE_method_set_delete_function(STORE_METHOD *sm, STORE_HANDLE_OBJECT_FUNC_PTR delete_f);
int STORE_method_set_list_start_function(STORE_METHOD *sm, STORE_START_OBJECT_FUNC_PTR list_start_f);
int STORE_method_set_list_next_function(STORE_METHOD *sm, STORE_NEXT_OBJECT_FUNC_PTR list_next_f);
int STORE_method_set_list_end_function(STORE_METHOD *sm, STORE_END_OBJECT_FUNC_PTR list_end_f);
int STORE_method_set_update_store_function(STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
int STORE_method_set_lock_store_function(STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
int STORE_method_set_unlock_store_function(STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
#endif

    if (!ENGINE_set_STORE(e, sm))
        return(0);

    return(1);
}
#endif /*ndef OPENSSL_NO_STORE*/
