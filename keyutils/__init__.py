#!/usr/bin/python
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

from __future__ import absolute_import

from typing import Optional, Union

from . import _keyutils


for k, v in _keyutils.constants.__dict__.items():
    globals()[k] = v
del k, v

from errno import (  # noqa: F401,E402 , imported for reexport; TODO: better reexport
    EACCES,
    EDQUOT,
    EINTR,
    EINVAL,
    ENOMEM,
)


KeyutilsError = _keyutils.error


def _handle_keyerror(err: Exception):
    if err.args[0] == _keyutils.constants.ENOKEY:
        return None
    raise err


def add_key(desc, value, keyring, keyType=b"user"):
    return _keyutils.add_key(keyType, desc, value, keyring)


def add_ring(desc, keyring) -> Optional[int]:
    return _keyutils.add_key(b"keyring", desc, None, keyring)


def request_key(keyDesc, keyring, keyType=b"user", callout_info=None):
    try:
        return _keyutils.request_key(keyType, keyDesc, callout_info, keyring)
    except KeyutilsError as err:
        return _handle_keyerror(err)


def get_keyring_id(key, create: bool):
    try:
        return _keyutils.get_keyring_id(key, create)
    except KeyutilsError as err:
        return _handle_keyerror(err)


def join_session_keyring(name=None):
    return _keyutils.join_session_keyring(name)


def update_key(key, value):
    return _keyutils.update_key(key, value)


def revoke(key):
    return _keyutils.revoke(key)


def chown(key, uid: Union[int, None], gid: Union[int, None]) -> None:
    if uid is None:
        uid = -1
    if gid is None:
        gid = -1
    # TODO: map other errors
    return _keyutils.chown(key, uid, gid)


def set_perm(key, perm):
    return _keyutils.set_perm(key, perm)


def clear(keyring):
    """Clear the keyring."""
    return _keyutils.clear(keyring)


def link(key, keyring):
    return _keyutils.link(key, keyring)


def unlink(key, keyring):
    return _keyutils.unlink(key, keyring)


def search(keyring, description, destination=0, keyType=b"user"):
    try:
        return _keyutils.search(keyring, keyType, description, destination)
    except KeyutilsError as err:
        return _handle_keyerror(err)


instantiate = _keyutils.instantiate


def negate(key, keyring, timeout=0):
    return _keyutils.negate(key, timeout, keyring)


def set_timeout(key, timeout):
    """Set timeout in seconds (int)."""
    return _keyutils.set_timeout(key, timeout)


def assume_authority(key):
    return _keyutils.assume_authority(key)


def session_to_parent():
    return _keyutils.session_to_parent()


def reject(key, keyring, error, timeout=0):
    return _keyutils.reject(key, timeout, error, keyring)


def invalidate(key):
    return _keyutils.invalidate(key)


def get_persistent(uid, key):
    return _keyutils.get_persistent(uid, key)


def dh_compute(key_priv, key_prime, key_base):
    return _keyutils.dh_compute(key_priv, key_prime, key_base)


def dh_compute_kdf(key_priv, key_prime, key_base, hashname, buflen, otherinfo=None):
    return _keyutils.dh_compute_kdf(key_priv, key_prime, key_base, hashname, buflen, otherinfo)


def restrict_keyring(keyring, key_type, restriction):
    return _keyutils.restrict_keyring(keyring, key_type, restriction)


def pkey_query(key, info: bytes = b''):
    return _keyutils.pkey_query(key, info)


def pkey_encrypt(key, data: bytes, info: bytes = b'') -> bytes:
    return _keyutils.pkey_encrypt(key, info, data)


def pkey_decrypt(key, enc: bytes, info: bytes = b'') -> bytes:
    return _keyutils.pkey_decrypt(key, info, enc)


def pkey_sign(key, data: bytes, info: bytes = b'') -> bytes:
    return _keyutils.pkey_sign(key, info, data)


def pkey_verify(key, data: bytes, sig: bytes, info: bytes = b'') -> bytes:
    return _keyutils.pkey_verify(key, info, data, sig)


def move(key, from_ringid, to_ringid, flags=0):
    return _keyutils.move(key, from_ringid, to_ringid, flags)


def capabilities() -> bytes:
    return _keyutils.capabilities()


def describe_key(keyId):
    return _keyutils.describe_key(keyId)


def read_key(keyId):
    return _keyutils.read_key(keyId)


def get_security(keyid):
    return _keyutils.get_security(keyid)
