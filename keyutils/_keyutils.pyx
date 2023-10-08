# cython: language_level=3
#
# Copyright (c) SAS Institute Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from libc cimport stdlib
from cython.cimports.keyutils import ckeyutils

cdef extern from "Python.h":
    object PyErr_SetFromErrno(exc)
    object PyBytes_FromStringAndSize(char *str, Py_ssize_t size)


class error(Exception):
    pass


class constants:
    KEY_SPEC_THREAD_KEYRING = ckeyutils.KEY_SPEC_THREAD_KEYRING
    KEY_SPEC_PROCESS_KEYRING = ckeyutils.KEY_SPEC_PROCESS_KEYRING
    KEY_SPEC_SESSION_KEYRING = ckeyutils.KEY_SPEC_SESSION_KEYRING
    KEY_SPEC_USER_KEYRING = ckeyutils.KEY_SPEC_USER_KEYRING
    KEY_SPEC_USER_SESSION_KEYRING = ckeyutils.KEY_SPEC_USER_SESSION_KEYRING
    KEY_SPEC_GROUP_KEYRING = ckeyutils.KEY_SPEC_GROUP_KEYRING
    KEY_SPEC_REQKEY_AUTH_KEY = ckeyutils.KEY_SPEC_REQKEY_AUTH_KEY
    ENOKEY = ckeyutils.ENOKEY
    EKEYEXPIRED = ckeyutils.EKEYEXPIRED
    EKEYREVOKED = ckeyutils.EKEYREVOKED
    EKEYREJECTED = ckeyutils.EKEYREJECTED
    KEY_POS_VIEW = ckeyutils.KEY_POS_VIEW
    KEY_POS_READ = ckeyutils.KEY_POS_READ
    KEY_POS_WRITE = ckeyutils.KEY_POS_WRITE
    KEY_POS_SEARCH = ckeyutils.KEY_POS_SEARCH
    KEY_POS_LINK = ckeyutils.KEY_POS_LINK
    KEY_POS_SETATTR = ckeyutils.KEY_POS_SETATTR
    KEY_POS_ALL = ckeyutils.KEY_POS_ALL
    KEY_USR_VIEW = ckeyutils.KEY_USR_VIEW
    KEY_USR_READ = ckeyutils.KEY_USR_READ
    KEY_USR_WRITE = ckeyutils.KEY_USR_WRITE
    KEY_USR_SEARCH = ckeyutils.KEY_USR_SEARCH
    KEY_USR_LINK = ckeyutils.KEY_USR_LINK
    KEY_USR_SETATTR = ckeyutils.KEY_USR_SETATTR
    KEY_USR_ALL = ckeyutils.KEY_USR_ALL
    KEY_GRP_VIEW = ckeyutils.KEY_GRP_VIEW
    KEY_GRP_READ = ckeyutils.KEY_GRP_READ
    KEY_GRP_WRITE = ckeyutils.KEY_GRP_WRITE
    KEY_GRP_SEARCH = ckeyutils.KEY_GRP_SEARCH
    KEY_GRP_LINK = ckeyutils.KEY_GRP_LINK
    KEY_GRP_SETATTR = ckeyutils.KEY_GRP_SETATTR
    KEY_GRP_ALL = ckeyutils.KEY_GRP_ALL
    KEY_OTH_VIEW = ckeyutils.KEY_OTH_VIEW
    KEY_OTH_READ = ckeyutils.KEY_OTH_READ
    KEY_OTH_WRITE = ckeyutils.KEY_OTH_WRITE
    KEY_OTH_SEARCH = ckeyutils.KEY_OTH_SEARCH
    KEY_OTH_LINK = ckeyutils.KEY_OTH_LINK
    KEY_OTH_SETATTR = ckeyutils.KEY_OTH_SETATTR
    KEY_OTH_ALL = ckeyutils.KEY_OTH_ALL


def add_key(bytes key_type, bytes description, bytes payload, int keyring):
    cdef int rc
    cdef char *key_type_p = key_type
    cdef char *desc_p = description
    cdef int payload_len
    cdef char *payload_p
    if payload is None:
        payload_p = NULL
        payload_len = 0
    else:
        payload_p = payload
        payload_len = len(payload)
    with nogil:
        rc = ckeyutils.add_key(key_type_p, desc_p, payload_p, payload_len, keyring)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return rc


def request_key(bytes key_type, bytes description, bytes callout_info, int keyring):
    cdef char *key_type_p = key_type
    cdef char *desc_p = description
    cdef char *callout_p
    cdef int rc
    if callout_info is None:
        callout_p = NULL
    else:
        callout_p = callout_info
    with nogil:
        rc = ckeyutils.request_key(key_type_p, desc_p, callout_p, keyring)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return rc


def search(int keyring, bytes key_type, bytes description, int destination):
    cdef char *key_type_p = key_type
    cdef char *desc_p = description
    cdef int rc
    with nogil:
        rc = ckeyutils.search(keyring, key_type_p, desc_p, destination)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return rc


def update_key(int key, bytes payload):
    cdef int rc
    cdef int payload_len
    cdef char *payload_p
    if payload is None:
        payload_p = NULL
        payload_len = 0
    else:
        payload_p = payload
        payload_len = len(payload)
    with nogil:
        rc = ckeyutils.update(key, payload_p, payload_len)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return None


def read_key(int key):
    cdef int size
    cdef void *ptr
    cdef bytes obj
    with nogil:
        size = ckeyutils.read_alloc(key, &ptr)
    if size < 0:
        PyErr_SetFromErrno(error)
    else:
        obj = PyBytes_FromStringAndSize(<char*>ptr, size)
        stdlib.free(ptr)
        return obj


def describe_key(int key):
    cdef int size
    cdef char *ptr
    cdef bytes obj
    with nogil:
        size = ckeyutils.describe_alloc(key, &ptr)
    if size < 0:
        PyErr_SetFromErrno(error)
    else:
        obj = PyBytes_FromStringAndSize(<char*>ptr, size)
        stdlib.free(ptr)
        return obj


def join_session_keyring(name):
    cdef char *name_p
    cdef int rc
    if name is None:
        name_p = NULL
    else:
        name_p = name
    with nogil:
        rc = ckeyutils.join_session_keyring(name_p)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return rc


def session_to_parent():
    cdef int rc
    with nogil:
        rc = ckeyutils.session_to_parent()
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return None


def link(int key, int keyring):
    cdef int rc
    with nogil:
        rc = ckeyutils.link(key, keyring)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return None


def unlink(int key, int keyring):
    cdef int rc
    with nogil:
        rc = ckeyutils.unlink(key, keyring)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return None


def revoke(int key):
    cdef int rc
    with nogil:
        rc = ckeyutils.revoke(key)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return None


def set_perm(int key, int perm):
    cdef int rc
    cdef int keyperm
    with nogil:
        rc = ckeyutils.setperm(key, perm)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return None


def set_timeout(int key, int timeout):
    cdef int rc
    with nogil:
        rc = ckeyutils.set_timeout(key, timeout)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return None


def clear(int keyring):
    cdef int rc
    with nogil:
        rc = ckeyutils.clear(keyring)
    if rc < 0:
        PyErr_SetFromErrno(error)
    else:
        return None
