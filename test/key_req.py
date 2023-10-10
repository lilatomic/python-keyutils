#!/tmp/venv/bin/python3
import sys


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


if __name__ == "__main__":
    report(sys.argv)
    if len(sys.argv) != 5:
        raise ValueError("need to pass 4 arguments")

    _, keyid, desc, callout, keyring_id = sys.argv
    try:
        debug(int(keyid), desc, callout, int(keyring_id))
    except Exception as e:
        report(e)
        sys.exit(1)
    sys.exit(0)
