cdef extern from "keyutils.h" nogil:
    # special process keyring shortcut IDs
    int KEY_SPEC_THREAD_KEYRING "KEY_SPEC_THREAD_KEYRING"
    int KEY_SPEC_PROCESS_KEYRING "KEY_SPEC_PROCESS_KEYRING"
    int KEY_SPEC_SESSION_KEYRING "KEY_SPEC_SESSION_KEYRING"
    int KEY_SPEC_USER_KEYRING "KEY_SPEC_USER_KEYRING"
    int KEY_SPEC_USER_SESSION_KEYRING "KEY_SPEC_USER_SESSION_KEYRING"
    int KEY_SPEC_GROUP_KEYRING "KEY_SPEC_GROUP_KEYRING"
    int KEY_SPEC_REQKEY_AUTH_KEY "KEY_SPEC_REQKEY_AUTH_KEY"

    int KEY_POS_VIEW "KEY_POS_VIEW"
    int KEY_POS_READ "KEY_POS_READ"
    int KEY_POS_WRITE "KEY_POS_WRITE"
    int KEY_POS_SEARCH "KEY_POS_SEARCH"
    int KEY_POS_LINK "KEY_POS_LINK"
    int KEY_POS_SETATTR "KEY_POS_SETATTR"
    int KEY_POS_ALL "KEY_POS_ALL"

    # user permissions...
    int KEY_USR_VIEW "KEY_USR_VIEW"
    int KEY_USR_READ "KEY_USR_READ"
    int KEY_USR_WRITE "KEY_USR_WRITE"
    int KEY_USR_SEARCH "KEY_USR_SEARCH"
    int KEY_USR_LINK "KEY_USR_LINK"
    int KEY_USR_SETATTR "KEY_USR_SETATTR"
    int KEY_USR_ALL "KEY_USR_ALL"

    # group permissions...
    int KEY_GRP_VIEW "KEY_GRP_VIEW"
    int KEY_GRP_READ "KEY_GRP_READ"
    int KEY_GRP_WRITE "KEY_GRP_WRITE"
    int KEY_GRP_SEARCH "KEY_GRP_SEARCH"
    int KEY_GRP_LINK "KEY_GRP_LINK"
    int KEY_GRP_SETATTR "KEY_GRP_SETATTR"
    int KEY_GRP_ALL "KEY_GRP_ALL"

    # third party permissions...
    int KEY_OTH_VIEW "KEY_OTH_VIEW"
    int KEY_OTH_READ "KEY_OTH_READ"
    int KEY_OTH_WRITE "KEY_OTH_WRITE"
    int KEY_OTH_SEARCH "KEY_OTH_SEARCH"
    int KEY_OTH_LINK "KEY_OTH_LINK"
    int KEY_OTH_SETATTR "KEY_OTH_SETATTR"
    int KEY_OTH_ALL "KEY_OTH_ALL"

    int ENOKEY "ENOKEY"
    int EKEYEXPIRED "EKEYEXPIRED"
    int EKEYREVOKED "EKEYREVOKED"
    int EKEYREJECTED "EKEYREJECTED"
    int add_key "add_key"(char *key_type, char *description, void *payload, int plen, int keyring)
    int request_key "request_key"(char *key_type, char *description, char *callout_info, int keyring)
    int search "keyctl_search"(int keyring, char *key_type, char *description, int destination)
    int update "keyctl_update"(int key, const void *payload, size_t plen)
    int read_alloc "keyctl_read_alloc"(int key, void **bufptr)
    int join_session_keyring "keyctl_join_session_keyring"(char *name)
    int session_to_parent "keyctl_session_to_parent"()
    int link "keyctl_link"(int key, int keyring)
    int unlink "keyctl_unlink"(int key, int keyring)
    int revoke "keyctl_revoke"(int key)
    int setperm "keyctl_setperm"(int key, int perm)
    int set_timeout "keyctl_set_timeout" (int key, int timeout)
    int clear "keyctl_clear" (int keyring)
    int describe_alloc "keyctl_describe_alloc" (int key, char **bufptr)
