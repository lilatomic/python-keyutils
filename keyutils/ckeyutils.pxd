from libc.stdint cimport int32_t, uint32_t

cdef extern from "keyutils.h" nogil:
    ctypedef int32_t key_serial_t
    ctypedef uint32_t uid_t
    ctypedef uint32_t gid_t

    cdef struct keyctl_pkey_query:
        unsigned int	supported_ops;	#  Which ops are supported
        unsigned int	key_size;	#  Size of the key in bits
        unsigned short	max_data_size;	#  Maximum size of raw data to sign in bytes
        unsigned short	max_sig_size;	#  Maximum size of signature in bytes
        unsigned short	max_enc_size;	#  Maximum size of encrypted blob in bytes
        unsigned short	max_dec_size;	#  Maximum size of decrypted blob in bytes
        unsigned int	__spare[10];


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

    # keyctl_move flags
    int KEYCTL_MOVE_EXCL "KEYCTL_MOVE_EXCL"

    # keyctl_capabilities output fields
    int KEYCTL_CAPS0_CAPABILITIES "KEYCTL_CAPS0_CAPABILITIES"
    int KEYCTL_CAPS0_PERSISTENT_KEYRINGS "KEYCTL_CAPS0_PERSISTENT_KEYRINGS"
    int KEYCTL_CAPS0_DIFFIE_HELLMAN "KEYCTL_CAPS0_DIFFIE_HELLMAN"
    int KEYCTL_CAPS0_PUBLIC_KEY "KEYCTL_CAPS0_PUBLIC_KEY"
    int KEYCTL_CAPS0_BIG_KEY "KEYCTL_CAPS0_BIG_KEY"
    int KEYCTL_CAPS0_INVALIDATE "KEYCTL_CAPS0_INVALIDATE"
    int KEYCTL_CAPS0_RESTRICT_KEYRING "KEYCTL_CAPS0_RESTRICT_KEYRING"
    int KEYCTL_CAPS0_MOVE "KEYCTL_CAPS0_MOVE"
    # int KEYCTL_CAPS1_NS_KEYRING_NAME "KEYCTL_CAPS1_NS_KEYRING_NAME"
    # int KEYCTL_CAPS1_NS_KEY_TAG "KEYCTL_CAPS1_NS_KEY_TAG"
    # int KEYCTL_CAPS1_NOTIFICATIONS "KEYCTL_CAPS1_NOTIFICATIONS"

    int add_key "add_key"(char *key_type, char *description, void *payload, int plen, int keyring)
    int request_key "request_key"(char *key_type, char *description, char *callout_info, int keyring)
    key_serial_t get_keyring_id "keyctl_get_keyring_ID"(key_serial_t key, int create)
    int join_session_keyring "keyctl_join_session_keyring"(char *name)
    int update "keyctl_update"(int key, const void *payload, size_t plen)
    int revoke "keyctl_revoke"(int key)
    int chown "keyctl_chown"(key_serial_t key, uid_t uid, gid_t gid);
    int setperm "keyctl_setperm"(int key, int perm)
    int clear "keyctl_clear"(int keyring)
    int link "keyctl_link"(int key, int keyring)
    int unlink "keyctl_unlink"(int key, int keyring)
    int search "keyctl_search"(int keyring, char *key_type, char *description, int destination)
    int instantiate "keyctl_instantiate"(key_serial_t key, const void *payload, size_t plen, key_serial_t keyring)
    int negate "keyctl_negate"(key_serial_t key, unsigned int timeout, key_serial_t keyring)
    int set_timeout "keyctl_set_timeout"(int key, int timeout)
    int assume_authority "keyctl_assume_authority"(key_serial_t key)
    int session_to_parent "keyctl_session_to_parent"()
    int reject "keyctl_reject"(key_serial_t key, unsigned int timeout, unsigned int error, key_serial_t keyring)
    int invalidate "keyctl_invalidate"(key_serial_t key)
    int get_persistent "keyctl_get_persistent"(uid_t uid, key_serial_t key)
    int dh_compute_kdf "keyctl_dh_compute_kdf"(key_serial_t priv, key_serial_t prime, key_serial_t base, char *hashname, char *otherinfo, int otherinfolen, char *buffer, size_t buflen)
    int dh_compute_alloc "keyctl_dh_compute_alloc"(key_serial_t priv, key_serial_t prime, key_serial_t base, void **bufptr)
    int restrict_keyring "keyctl_restrict_keyring"(key_serial_t keyring, const char *key_type, const char *restriction)
    int pkey_query "keyctl_pkey_query"(key_serial_t key, const char *info, keyctl_pkey_query *result)
    int pkey_encrypt "keyctl_pkey_encrypt"(key_serial_t key, const char* info, const void *data, size_t data_len, void *enc, size_t enc_len)
    int pkey_decrypt "keyctl_pkey_decrypt"(key_serial_t key, const char* info, void *enc, size_t enc_len, const void *data, size_t data_len)
    int pkey_sign "keyctl_pkey_sign"(key_serial_t key, const char* info, const void *data, size_t data_len, void *sig, size_t sig_len)
    int pkey_verify "keyctl_pkey_verify"(key_serial_t key, const char* info, const void *data, size_t data_len, void *sig, size_t sig_len)
    int move "keyctl_move"(key_serial_t key, key_serial_t from_ringid, key_serial_t to_ringid, unsigned int flags)
    int capabilities "keyctl_capabilities"(unsigned char *buffer, size_t buflen)
    int describe_alloc "keyctl_describe_alloc"(int key, char **bufptr)
    int read_alloc "keyctl_read_alloc"(int key, void ** bufptr)
    int get_security_alloc "keyctl_get_security_alloc"(key_serial_t key, char **bufptr)
