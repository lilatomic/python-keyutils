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


import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

import pytest

import keyutils
from test import crypt_utils


def has_sudo():
    """
    Test that we have root capabilities which we need for privileged key operations
    """
    proc = subprocess.run(["sudo", "-v", "-n"], capture_output=True, text=True)
    return proc.returncode == 0


needs_sudo = pytest.mark.skipif(not has_sudo(), reason="requires sudo permissions")


@pytest.fixture(scope="function")
def ring(request):
    return keyutils.add_ring(request.function.__name__.encode("utf-8"), keyutils.KEY_SPEC_THREAD_KEYRING)


def rings(parent: int, n: int = 2):
    rings = []
    for i in range(0, n):
        rings.append(keyutils.add_ring(str(i).encode("utf-8"), parent))
    return rings


class BasicTest(unittest.TestCase):
    def testSet(self):
        keyDesc = b"test:key:01"
        keyVal = b"key value with\0 some weird chars in it too"
        keyring = keyutils.KEY_SPEC_THREAD_KEYRING

        # Key not initialized; should get None
        keyId = keyutils.request_key(keyDesc, keyring)
        self.assertEqual(keyId, None)

        self.assertRaises(keyutils.KeyutilsError, keyutils.read_key, 12345)
        try:
            keyutils.read_key(12345)
        except keyutils.KeyutilsError as e:
            self.assertEqual(e.args, (126, "Required key not available"))

        keyutils.add_key(keyDesc, keyVal, keyring)
        keyId = keyutils.request_key(keyDesc, keyring)

        data = keyutils.read_key(keyId)
        self.assertEqual(data, keyVal)

    def testSession(self):
        desc = b"test:key:02"
        val = b"asdfasdfasdf"
        session = keyutils.join_session_keyring()
        keyId = keyutils.add_key(desc, val, session)
        self.assertEqual(
            keyutils.search(keyutils.KEY_SPEC_SESSION_KEYRING, desc), keyId
        )
        keyutils.join_session_keyring()
        self.assertEqual(keyutils.search(keyutils.KEY_SPEC_SESSION_KEYRING, desc), None)

    def testRevoke(self):
        desc = b"dummy"
        session = keyutils.join_session_keyring()
        self.assertEqual(keyutils.search(keyutils.KEY_SPEC_SESSION_KEYRING, desc), None)
        keyutils.revoke(session)
        try:
            keyutils.search(keyutils.KEY_SPEC_SESSION_KEYRING, desc)
        except keyutils.KeyutilsError as err:
            self.assertEqual(err.args[0], keyutils.EKEYREVOKED)
        else:
            self.fail("Expected keyutils.Error")

        # It is convenient to use this test to verify that session_to_parent()
        # is functional because at this point it is known that there is
        # no session keyring available.

        childpid = os.fork()
        if childpid:
            pid, exitcode = os.waitpid(childpid, 0)
            self.assertEqual(childpid, pid)
            self.assertTrue(
                os.WIFEXITED(exitcode) and os.WEXITSTATUS(exitcode) == 0, exitcode
            )
        else:
            rc = 1
            try:
                keyutils.join_session_keyring()
                keyutils.session_to_parent()
                rc = 0
            finally:
                os._exit(rc)

        self.assertEqual(keyutils.search(keyutils.KEY_SPEC_SESSION_KEYRING, desc), None)

    def testLink(self):
        desc = b"key1"
        child = keyutils.add_key(
            b"ring1", None, keyutils.KEY_SPEC_PROCESS_KEYRING, b"keyring"
        )
        parent = keyutils.add_key(
            b"ring2", None, keyutils.KEY_SPEC_PROCESS_KEYRING, b"keyring"
        )
        keyId = keyutils.add_key(desc, b"dummy", child)
        self.assertEqual(keyutils.search(child, desc), keyId)
        self.assertEqual(keyutils.search(parent, desc), None)
        keyutils.link(child, parent)
        self.assertEqual(keyutils.search(parent, desc), keyId)

        keyutils.unlink(child, parent)
        self.assertEqual(keyutils.search(parent, desc), None)

    def testTimeout(self):
        desc = b"dummyKey"
        value = b"dummyValue"
        keyring = keyutils.KEY_SPEC_THREAD_KEYRING

        # create key with 1 second timeout:
        keyId = keyutils.add_key(desc, value, keyring)
        self.assertEqual(keyutils.request_key(desc, keyring), keyId)

        keyutils.set_timeout(keyId, 1)
        time.sleep(1.5)
        try:
            keyId = keyutils.request_key(desc, keyring)
        except keyutils.KeyutilsError as err:
            # https://patchwork.kernel.org/patch/5336901
            self.assertEqual(err.args[0], keyutils.EKEYEXPIRED)
            keyId = None
        self.assertEqual(keyId, None)

    def testClear(self):
        desc = b"dummyKey"
        value = b"dummyValue"
        keyring = keyutils.KEY_SPEC_THREAD_KEYRING

        key_id = keyutils.add_key(desc, value, keyring)

        self.assertEqual(keyutils.request_key(desc, keyring), key_id)
        keyutils.clear(keyring)
        self.assertRaises(keyutils.KeyutilsError, keyutils.read_key, key_id)

    def testDescribe(self):
        desc = b"dummyKey"
        value = b"dummyValue"
        keyring = keyutils.KEY_SPEC_THREAD_KEYRING

        key_id = keyutils.add_key(desc, value, keyring)

        ret = keyutils.describe_key(key_id)
        ktype, _, _, kperm, kdesc = ret.split(b";", 4)
        self.assertEqual(ktype, b"user")
        self.assertEqual(desc, kdesc)

    def testUpdate(self):
        desc = b"dummyKey"
        value = b"dummyValue1"
        keyring = keyutils.KEY_SPEC_THREAD_KEYRING

        key_id = keyutils.add_key(desc, value, keyring)

        self.assertEqual(b"dummyValue1", keyutils.read_key(key_id))
        keyutils.update_key(key_id, b"dummyValue2")
        self.assertEqual(b"dummyValue2", keyutils.read_key(key_id))

    def testSetPerm(self):
        desc = b"dummyKey"
        value = b"dummyValue1"
        keyring = keyutils.KEY_SPEC_THREAD_KEYRING

        key_id = keyutils.add_key(desc, value, keyring)

        ktype, _, _, kperm, kdesc = keyutils.describe_key(key_id).split(b";", 4)
        kperm = int(kperm, base=16)
        self.assertEqual(keyutils.KEY_POS_READ, kperm & keyutils.KEY_POS_READ)
        keyutils.set_perm(key_id, kperm - keyutils.KEY_POS_READ)

        ktype, _, _, kperm, kdesc = keyutils.describe_key(key_id).split(b";", 4)
        kperm = int(kperm, base=16)
        self.assertEqual(0, kperm & keyutils.KEY_POS_READ)

    def testInvalidate(self):
        value = b"invalidate_v"
        key_id = keyutils.add_key(b"invalidate_n", value, keyutils.KEY_SPEC_THREAD_KEYRING)
        assert key_id
        key_value = keyutils.read_key(key_id)
        assert key_value == value

        keyutils.invalidate(key_id)

        with pytest.raises(keyutils.KeyutilsError):  # TODO: more specific error check
            keyutils.read_key(key_id)


class TestBasic:

    def testGetPersistent(self, ring):
        bytes_per_key = 4  # TODO: better calculated
        keys = keyutils.read_key(ring)
        assert len(keys) == 0
        key_id = keyutils.get_persistent(os.getuid(), ring)
        keys = keyutils.read_key(ring)
        assert len(keys) == bytes_per_key
        assert key_id == int.from_bytes(keys, sys.byteorder)

    def testGetSecurity(self, ring):
        security = keyutils.get_security(ring)
        assert security == b''  # TODO: find out how to apply security labels

    def test_move(self, ring):
        children = rings(ring, 2)
        key = keyutils.add_key(b"test_move_k", b"test_move_v", children[0])

        keyutils.move(key, children[0], children[1])

    def test_move_exclusive(self, ring):
        r_from, r_to = rings(ring, 2)
        key = keyutils.add_key(b"test_move_k", b"test_move_v", r_from)
        keyutils.link(key, r_to)

        with pytest.raises(keyutils.KeyutilsError) as e:
            keyutils.move(key, r_from, r_to, keyutils.KEYCTL_MOVE_EXCL)
        assert e.value.args[1] == 'File exists'

    def test_capabilities(self):
        caps = keyutils.capabilities()
        assert caps
        assert not caps.startswith(b'\x00')  # the first byte will contain the results, and it should contain _something_


def test_get_keyring_id():
    keyring = keyutils.get_keyring_id(keyutils.KEY_SPEC_THREAD_KEYRING, False)
    assert keyring is not None and keyring != 0


@pytest.mark.xfail(reason="Not implemented")
@needs_sudo
def test_keyring_chown(self):
    # TODO: implement this
    keyutils.add_key(b"chown_n", b"chown_v", keyutils.KEY_SPEC_THREAD_KEYRING)
    raise NotImplementedError()


@pytest.fixture
def request_key(tmpdir):
    subprocess.run(["sudo", "-n", sys.executable, Path(__file__).parent / "key_req.py", tmpdir, "True"])
    yield
    subprocess.run(["sudo", "-n", sys.executable, Path(__file__).parent / "key_req.py", tmpdir, "False"])


@needs_sudo
class TestInstantiate:
    def test_instantiate(self, request_key):
        key = keyutils.request_key(b"turkeyutils:instantiate", keyutils.KEY_SPEC_THREAD_KEYRING, callout_info=b"pytest")

        assert key
        key_value = keyutils.read_key(key)
        assert key_value == b'Debug pytest'

    def test_negate(self, request_key):
        key = keyutils.request_key(b"turkeyutils:negate", keyutils.KEY_SPEC_THREAD_KEYRING, callout_info=b"negate")

        assert not key

    def test_reject(self, request_key):
        with pytest.raises(keyutils.KeyutilsError) as e:
            keyutils.request_key(b"turkeyutils:reject", keyutils.KEY_SPEC_THREAD_KEYRING, callout_info=b"reject")
        assert e.value.args[0] == 128

    def test_instantiation_failed(self, request_key):
        key = keyutils.request_key(b"aaaa:aaaa", keyutils.KEY_SPEC_THREAD_KEYRING, callout_info=b"pytest")
        assert key is None


@pytest.fixture
def dh_keys(tmpdir):
    # TODO: this is a shim to make things go faster
    regen = not Path("/tmp/dh/dh.pem").exists()
    out = Path("/tmp/dh")

    return crypt_utils.extract_dh_keyring_items(*crypt_utils.dh_keys(out, regen=regen))


class TestDH:
    def test_compute(self, dh_keys):
        keys = {k: keyutils.add_key(k.encode("utf-8"), v, keyutils.KEY_SPEC_THREAD_KEYRING) for k, v in dh_keys.items()}

        v = keyutils.dh_compute(keys["dh_priv"], keys["dh_prime"], keys["dh_base"])
        assert v
        assert len(v) == 520

    def test_kdf(self, dh_keys):
        keys = {k: keyutils.add_key(k.encode("utf-8"), v, keyutils.KEY_SPEC_THREAD_KEYRING) for k, v in dh_keys.items()}

        v = keyutils.dh_compute_kdf(keys["dh_priv"], keys["dh_prime"], keys["dh_base"], b"sha512", 1024)
        assert v
        assert len(v) == 1024


@pytest.fixture
def rsa_keys(tmpdir):
    regen = not Path("/tmp/rsa/ca/rsa.pem").exists()
    out = Path("/tmp/rsa")

    return crypt_utils.rsa_keys(out, regen=regen)


class TestRestrict:
    def test_block_all(self, ring):
        keyutils.restrict_keyring(ring, None, None)

        with pytest.raises(keyutils.KeyutilsError) as e:
            keyutils.add_key(b"test_restrict_n", b"test_restrict_v", ring)
        assert e.value.args[1] == 'Operation not permitted'

    def test_restrict_keyring(self, rsa_keys):
        allowed_ring = keyutils.add_ring(b"test_restrict_keyring_allowed", keyutils.KEY_SPEC_THREAD_KEYRING)
        allowed_key = keyutils.add_key(b"restrict_allowed", rsa_keys["ca"], allowed_ring, b"asymmetric")
        target_ring = keyutils.add_ring(b"test_restrict_keyring_target", keyutils.KEY_SPEC_THREAD_KEYRING)

        print(f"key_or_keyring:{allowed_ring}")
        keyutils.restrict_keyring(target_ring, b"asymmetric", f"key_or_keyring:{allowed_ring}".encode("ascii"))

        # check we can add a permitted key
        keyutils.link(allowed_key, target_ring)
        # check we can't add user keys
        with pytest.raises(keyutils.KeyutilsError) as e:
            keyutils.add_key(b"test_restrict_user", b"test_restrict_v", target_ring)
        assert e.value.args[1] == 'Operation not supported'
        # check we can't add a random x509
        with pytest.raises(keyutils.KeyutilsError) as e:
            keyutils.add_key(b"test_restrict_unsigned", rsa_keys["unsigned"], target_ring, b"asymmetric")
        assert e.value.args[1] == 'Required key not available'
        # check we can add a signed key
        leaf_key = keyutils.add_key(b"test_restrict_leaf", rsa_keys["leaf"], target_ring, b"asymmetric")
        assert leaf_key


def supports_pkcs8():
    """
    We need the pkcs8_key_parser to be loaded in order to handle asymmetric operations
    Try loading it with `sudo modprobe pkcs8_key_parser`
    """
    lsmod = subprocess.run(["lsmod"], capture_output=True, text=True)
    return "pkcs8_key_parser" in lsmod.stdout


needs_pkcs8 = pytest.mark.skipif(not supports_pkcs8(), reason="requires pkcs8 parser to insert asymmetric keys")


class TestPKey:
    def test_query(self, ring, rsa_keys):
        pkey = keyutils.add_key(b"test_pkey", rsa_keys["ca"], ring, b"asymmetric")
        query_result = keyutils.pkey_query(pkey)
        assert query_result["key_size"] == 2048

    @needs_pkcs8
    def test_encrypt(self, ring, rsa_keys):
        pkey = keyutils.add_key(b"test_pkey_encrypt", rsa_keys["pkcs8"], ring, b"asymmetric")
        data = b"hihello".ljust(256, b"0")
        enc = keyutils.pkey_encrypt(pkey, data)
        assert enc
        dec = keyutils.pkey_decrypt(pkey, enc)
        assert dec == data

    @needs_pkcs8
    def test_sign(self, ring, rsa_keys):
        pkey = keyutils.add_key(b"test_pkey_verify", rsa_keys["pkcs8"], ring, b"asymmetric")
        # data = b"hihello".ljust(256, b"0")
        data = b"hihello"
        sig = keyutils.pkey_sign(pkey, data, info=b'enc=pkcs1 hash=sha256')
        assert len(sig) == 256
        verify = keyutils.pkey_verify(pkey, data, sig, info=b'enc=pkcs1 hash=sha256')
        assert verify == 0

        bad_data = b"some bad data"
        with pytest.raises(keyutils.KeyutilsError) as e:
            keyutils.pkey_verify(pkey, bad_data, sig, info=b'enc=pkcs1 hash=sha256')
        assert e.value.args[1] == 'Key was rejected by service'


if __name__ == "__main__":
    sys.exit(unittest.main())
