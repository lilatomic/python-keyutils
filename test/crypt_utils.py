"""Utilities to generate stub cryptographic elements"""
import base64
import re
import subprocess
from pathlib import Path


def read_pem_object(head: str, it):
    """Read a PEM object"""
    key_name = head[5:-5]
    if key_name.startswith("BEGIN "):
        key_name = key_name[len("BEGIN "):]
    key_data = ""
    for line in it:
        if line.startswith("-----"):  # trailer
            return key_name, key_data
        else:
            key_data += line.strip()
    raise StopIteration(f"Reached end of key block but did not find trailer. head is {key_name}")


def parse_openssl_text(ls):
    keys = []
    result = {}

    current_field = None
    current_data = ""

    lines = iter(ls)
    for line in lines:
        if line.startswith("-----"):
            # line begins a key
            key_name, key_data = read_pem_object(line, lines)
            keys.append((key_name, key_data,))

        elif not line.startswith(' '):
            line = line.strip()
            # This line represents a field name
            field_name_end = line.find(":")
            current_field = line[:field_name_end]

            if not line.endswith(":"):  # data is inline
                current_data = line[field_name_end + 1:].strip()
            else:
                current_data = ""  # Reset the data list for the new field

        elif current_field is not None and line:
            # This line contains hexadecimal data
            current_data += (line.strip())

        # Store the data for the current field
        if current_field is not None:
            result[current_field] = current_data

    return keys, result


def process_openssl_objects(objs: dict):
    out = {}
    for k, v in objs.items():
        if k in {"private-key", "public-key", "P"}:
            # out[k] = bytes.fromhex(v.replace(":", ""))
            out[k] = v.replace(":", "").encode("ascii")
        elif re.match(r"\d+ \(0x\d+\)", v):  # matches '2 (0x2)'
            match = re.match(r"\d+ \(0x(\d+)\)", v)
            out[k] = match.group(0).encode("utf-8")
            out[k] = b"02"  # TODO: this is a shim
        else:
            out[k] = v
    return out


def process_key_bodies(objs: list):
    out = []
    for k, v in objs:
        out.append((k, base64.b64decode(v),))
    return out


def gen_dh(workdir: Path, gen_dhparam: bool):
    if gen_dhparam:
        workdir.mkdir(exist_ok=True, parents=True)
        subprocess.run(["openssl", "dhparam", "-check", "-out", str(workdir / "dh.pem"), "2048"])

    keyinfo = subprocess.run(["openssl", "genpkey", "-paramfile", str(workdir / "dh.pem"), "-text"],
                             capture_output=True, text=True)

    return keyinfo.stdout


def dh_keys(workdir: Path, regen=True):
    openssl_output = gen_dh(workdir, regen).splitlines()
    keys, objects = parse_openssl_text(openssl_output)
    objects = process_openssl_objects(objects)
    keys = process_key_bodies(keys)
    return keys, objects


def extract_dh_keyring_items(keys, objects):
    return {
        "dh_priv": objects["private-key"],
        "dh_prime": objects["P"],
        "dh_base": objects["G"],
    }


def gen_rsa(workdir, regen: bool):
    privkey_path = str(workdir / "rsa.pem")
    if regen:
        workdir.mkdir(exist_ok=True, parents=True)
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", privkey_path])

    der_path = str(workdir / "rsa.x509.der")
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", privkey_path, "-outform", "DER", "-days", "365", "-out", der_path, "-subj", "/C=CA/O=example/CN=turkeyutils-ca"])

    with open(der_path, mode="rb") as der_file:
        der = der_file.read()
    with open(privkey_path, mode="rb") as privkey_file:
        key = privkey_file.read()

    return key, der


def gen_child_cert(workdir, cadir, regen: bool):
    privkey_path = str(workdir / "rsa.pem")
    if regen:
        workdir.mkdir(exist_ok=True, parents=True)
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", privkey_path])

    csr_path = str(workdir / "rsa.crt")
    der_path = str(workdir / "rsa.x509.der")

    subprocess.run(["openssl", "req", "-new", "-key", privkey_path, "-out", csr_path, "-subj", "/C=CA/O=example/CN=turkeyutils-leaf"])
    subprocess.run([
        "openssl",
        "x509",
        "-req",
        "-in",
        csr_path,
        "-CA",
        str(cadir / "rsa.x509.der"),
        "-CAkey", str(cadir / "rsa.pem"),
        "-CAcreateserial",
        "-days",
        "365",
        "-outform",
        "DER",
        "-out",
        der_path
    ])

    with open(der_path, mode="rb") as der_file:
        der = der_file.read()
    with open(privkey_path, mode="rb") as privkey_file:
        key = privkey_file.read()

    return key, der


def rsa_to_pkcs8(workdir):
    privkey_path = str(workdir / "rsa.pem")
    pkcs8_path = str(workdir / "rsa.pkcs8.der")

    subprocess.run(["openssl", "pkcs8", "-in", privkey_path, "-topk8", "-nocrypt", "-outform", "DER", "-out", pkcs8_path], check=True)

    with open(pkcs8_path, mode="rb") as pkcs8_file:
        pkcs8 = pkcs8_file.read()

    return pkcs8


def rsa_keys(workdir: Path, regen=True):
    ca_key, ca_cert = gen_rsa(workdir / "ca", regen)
    unsigned_key, unsigned_cert = gen_rsa(workdir / "unsigned", regen)
    leaf_key, leaf_cert = gen_child_cert(workdir / "leaf", workdir / "ca", regen)
    pkcs8 = rsa_to_pkcs8(workdir / "unsigned")
    return {
        "ca": ca_cert,
        "unsigned": unsigned_cert,
        "leaf": leaf_cert,
        "ca_key": ca_key,
        "unsigned_key": unsigned_key,
        "leaf_key": leaf_key,
        "pkcs8": pkcs8
    }


if __name__ == "__main__":
    keys, objects = dh_keys(Path.cwd(), regen=False)
    print(keys, objects)
