cdef extern from "keyutils.h" nogil:
    int c_KEY_SPEC_THREAD_KEYRING "KEY_SPEC_THREAD_KEYRING"
    int c_KEY_SPEC_PROCESS_KEYRING "KEY_SPEC_PROCESS_KEYRING"
    int c_KEY_SPEC_SESSION_KEYRING "KEY_SPEC_SESSION_KEYRING"
    int c_KEY_SPEC_USER_KEYRING "KEY_SPEC_USER_KEYRING"
    int c_KEY_SPEC_USER_SESSION_KEYRING "KEY_SPEC_USER_SESSION_KEYRING"
    int c_KEY_POS_VIEW "KEY_POS_VIEW"
    int c_KEY_POS_READ "KEY_POS_READ"
    int c_KEY_POS_WRITE "KEY_POS_WRITE"
    int c_KEY_POS_SEARCH "KEY_POS_SEARCH"
    int c_KEY_POS_LINK "KEY_POS_LINK"
    int c_KEY_POS_SETATTR "KEY_POS_SETATTR"
    int c_KEY_POS_ALL "KEY_POS_ALL"
    int c_KEY_USR_VIEW "KEY_USR_VIEW"
    int c_KEY_USR_READ "KEY_USR_READ"
    int c_KEY_USR_WRITE "KEY_USR_WRITE"
    int c_KEY_USR_SEARCH "KEY_USR_SEARCH"
    int c_KEY_USR_LINK "KEY_USR_LINK"
    int c_KEY_USR_SETATTR "KEY_USR_SETATTR"
    int c_KEY_USR_ALL "KEY_USR_ALL"
    int c_KEY_GRP_VIEW "KEY_GRP_VIEW"
    int c_KEY_GRP_READ "KEY_GRP_READ"
    int c_KEY_GRP_WRITE "KEY_GRP_WRITE"
    int c_KEY_GRP_SEARCH "KEY_GRP_SEARCH"
    int c_KEY_GRP_LINK "KEY_GRP_LINK"
    int c_KEY_GRP_SETATTR "KEY_GRP_SETATTR"
    int c_KEY_GRP_ALL "KEY_GRP_ALL"
    int c_KEY_OTH_VIEW "KEY_OTH_VIEW"
    int c_KEY_OTH_READ "KEY_OTH_READ"
    int c_KEY_OTH_WRITE "KEY_OTH_WRITE"
    int c_KEY_OTH_SEARCH "KEY_OTH_SEARCH"
    int c_KEY_OTH_LINK "KEY_OTH_LINK"
    int c_KEY_OTH_SETATTR "KEY_OTH_SETATTR"
    int c_KEY_OTH_ALL "KEY_OTH_ALL"
    int c_ENOKEY "ENOKEY"
    int c_EKEYEXPIRED "EKEYEXPIRED"
    int c_EKEYREVOKED "EKEYREVOKED"
    int c_EKEYREJECTED "EKEYREJECTED"
    int c_add_key "add_key"(char *key_type, char *description, void *payload,
            int plen, int keyring)
    int c_request_key "request_key"(char *key_type, char *description,
            char *callout_info, int keyring)
    int c_search "keyctl_search"(int keyring, char *key_type,
            char *description, int destination)
    int c_update "keyctl_update"(int key, const void *payload, size_t plen)
    int c_read_alloc "keyctl_read_alloc"(int key, void **bufptr)
    int c_join_session_keyring "keyctl_join_session_keyring"(char *name)
    int c_session_to_parent "keyctl_session_to_parent"()
    int c_link "keyctl_link"(int key, int keyring)
    int c_unlink "keyctl_unlink"(int key, int keyring)
    int c_revoke "keyctl_revoke"(int key)
    int c_setperm "keyctl_setperm"(int key, int perm)
    int c_set_timeout "keyctl_set_timeout" (int key, int timeout)
    int c_clear "keyctl_clear" (int keyring)
    int c_describe_alloc "keyctl_describe_alloc" (int key, char **bufptr)