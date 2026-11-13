import base64
import json
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from generate_vaults import deriveAuthHash, deriveKey  # same math as the generator

SERVER = "http://127.0.0.1:5001"

def call(method, path, body=None, headers=None):
    """Send one request to the mock server and return its JSON reply."""
    data = json.dumps(body).encode("utf-8") if body is not None else None  # dict -> bytes
    req = urllib.request.Request(SERVER + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as err:
        sys.exit(f"Server said {err.code}: {err.read().decode()}")

def unpad(data):
    """Strip the padding that pad() added in generate_vaults.py."""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def decrypt(key, field):
    """Undo encryptECB / encryptCBC from generate_vaults.py."""
    ciphertext = base64.b64decode(field["ciphertext"])  # base64 text -> bytes
    if field["mode"] == "ECB":
        mode = modes.ECB()
    else:
        mode = modes.CBC(base64.b64decode(field["iv"]))  # CBC needs the stored IV
    decryptor = Cipher(algorithms.AES(key), mode).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded).decode("utf-8")


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: python client.py <username> <master_password>")
    username, master_password = sys.argv[1], sys.argv[2]

    # key is derived here, only the auth hash leaves this machine
    iterations = call("GET", f"/iterations/{username}")["iterations"]
    key = deriveKey(master_password, username, iterations)
    auth_hash = deriveAuthHash(key, master_password)

    token = call("POST", "/login", {"username": username, "auth_hash": auth_hash})["token"]
    vault = call("GET", "/vault", headers={"Authorization": f"Bearer {token}"})

    print(f"Logged in as {username} ({iterations} iterations)")
    for entry in vault["entries"]:
        login = decrypt(key, entry["login"])
        password = decrypt(key, entry["password"])
        print(f"  {entry['url']:30} {login:20} {password}")


if __name__ == "__main__":
    main()