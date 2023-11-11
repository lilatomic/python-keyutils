#!/tmp/venv/bin/python3
import ast
import os
import sys
import textwrap
from pathlib import Path


def report(s):
    with open("/tmp/file.txt", mode="a") as f:
        f.write(str(s))
        f.write("\n")


def debug(keyid, desc, callout, keyring_id):
    import keyutils

    report(f"RQDebug keyid: {keyid}")
    report(f"RQDebug desc: {desc}")
    report(f"RQDebug callout: {callout}")
    report(f"RQDebug session keyring: {keyring_id}")

    if callout == "negate":
        report(f"keyctl negate {keyid} 30 {keyring_id}")
        keyutils.negate(keyid, keyring_id, 30)
    elif callout == "reject":
        report(f"keyctl reject {keyid} 30 {keyring_id}")
        # 128 is EKEYREVOKED
        keyutils.reject(keyid, keyring_id, error=128, timeout=30)
    else:
        report(f"keyctl instantiate {keyid} \"Debug {callout}\" {keyring_id}")
        keyutils.instantiate(keyid, f"Debug {callout}".encode("utf-8"), keyring_id)


def install(tmpdir, install):
    """Install the keyutils config file"""
    if install:
        report("install request-key handler")
        # Create a launcher script to get around a parser limitation in `/sbin/request-key`.
        # request-key will take the executable path as everything up to the last "/",
        # which is a problem for having both the python and the script file with absolute paths.
        # eg "/path/to/bin/python /path/to/script.py %k %d %c %S"
        # is parsed as ["/path/to/bin/python /path/to/script.py", "%k", "%d", "%c", "%S"]
        launcher_path = Path(tmpdir) / "key_req.sh"
        with open(launcher_path, mode="w", encoding="utf-8") as launcher:
            launcher.write(textwrap.dedent(f"""\
                #!/bin/bash
                {sys.executable} {Path(__file__)} $@
                """))
            os.chmod(launcher_path, 0o755)

        with open(Path("/etc/request-key.d/turkeyutils.conf"), mode="w", encoding="utf-8") as config:
            # add a config for to call into our executable for key requests
            config.write(textwrap.dedent(f"""\
                #OP     TYPE    DESCRIPTION     CALLOUT INFO    PROGRAM ARG1 ARG2 ARG3 ...
                #====== ======= =============== =============== ===============================
                create  user    turkeyutils:*   *               {launcher_path} %k %d %c %S
                """))
    else:
        report("uninstall request-key handler")
        Path("/etc/request-key.d/turkeyutils.conf").unlink(missing_ok=True)


if __name__ == "__main__":
    report(sys.argv)
    try:
        if len(sys.argv) == 5:
            _, keyid, desc, callout, keyring_id = sys.argv
            debug(int(keyid), desc, callout, int(keyring_id))
        elif len(sys.argv) == 3:
            _, tmpdir, install_raw = sys.argv
            install(tmpdir, bool(ast.literal_eval(install_raw)))
        else:
            raise ValueError("wrong number of args passed")
    except Exception as e:
        report(e)
        sys.exit(1)
    sys.exit(0)
