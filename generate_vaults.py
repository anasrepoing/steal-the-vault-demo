import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# fake users for demo, master passwords live here as well
USERS = [
    {
        "username": "amy@example.com",
        "master_password": "sunshine1",          # the easy target
        "iterations": 500,                       # old LastPass default
        "entries": 
        [
            {"url": "https://bank.example.com", "login": "amy", "password": "Fluffy2015", "mode": "ECB"},
            {"url": "https://mail.example.com", "login": "amy", "password": "Fluffy2015", "mode": "ECB"},  # reused!
            {"url": "https://shop.example.com", "login": "amy", "password": "x9!Lq2#v", "mode": "CBC"},
        ],
    },
    {
        "username": "bob@example.com",
        "master_password": "Baseball!42",
        "iterations": 5000,                      # later old default
        "entries": 
        [
            {"url": "https://social.example.com", "login": "bobby", "password": "Summer2019!", "mode": "ECB"},
            {"url": "https://stream.example.com", "login": "bob@example.com", "password": "T7#mq!Rz", "mode": "CBC"},
        ],
    },
    {
        "username": "carol@example.com",
        "master_password": "purple-otter-canyon-92",
        "iterations": 100100,                   # default from 2018
        "entries": 
        [
            {"url": "https://bank.example.com", "login": "carol", "password": "Wq8$zL!e3Pn", "mode": "CBC"},
            {"url": "https://work.example.com", "login": "carol.w", "password": "h4^Kd9@vMx", "mode": "CBC"},
        ],
    },
    {
        "username": "dave@example.com",
        "master_password": "Correct-Horse-Battery-77",
        "iterations": 600000,                    # modern recommendation
        "entries": 
        [
            {"url": "https://crypto.example.com", "login": "dave", "password": "Zr!8pQ#2nV6t", "mode": "CBC"},
            {"url": "https://mail.example.com", "login": "dave", "password": "m3@Lx9!Wq7", "mode": "CBC"},
        ],
    },
]

def deriveKey(master_password, username, iterations):
    """Run PBKDF2 to turn the master password into a 256-bit AES key."""
    return hashlib.pbkdf2_hmac(
        "sha256",                          # the hash function repeated each round
        master_password.encode("utf-8"),   # text -> bytes
        username.encode("utf-8"),          # the salt (LastPass used the email)
        iterations,                        # how many rounds (attacker's cost per guess)
        dklen=32,                          # 32 bytes = 256 bits
    )

def deriveAuthHash(key, master_password):
    """One more PBKDF2 round on the key -> the value the client sends to log in."""
    auth = hashlib.pbkdf2_hmac(
        "sha256",
        key,                               # the vault key from deriveKey
        master_password.encode("utf-8"),   # master password used as the salt
        1,                                 # a single round
        dklen=32,
    )
    return auth.hex()

def pad(data):
    """Fill out the last 16-byte block so AES can process it."""
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def toText(raw_bytes):
    """Convert raw bytes to base64 text so they can be saved in JSON."""
    return base64.b64encode(raw_bytes).decode("ascii")

def encryptECB(key, plaintext):
    """ECB: no IV, so the same input always gives the same output."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ciphertext = encryptor.update(pad(plaintext.encode("utf-8"))) + encryptor.finalize()
    return {"mode": "ECB", "ciphertext": toText(ciphertext)}


def encryptCBC(key, plaintext):
    """CBC: random IV each time, so identical inputs look different."""
    iv = os.urandom(16)  # 16 random bytes
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(pad(plaintext.encode("utf-8"))) + encryptor.finalize()
    # IV not secret, it's stored so the vault can be decrypted later.
    return {"mode": "CBC", "iv": toText(iv), "ciphertext": toText(ciphertext)}


def encrypt(key, plaintext, mode):
    """Pick the encryption mode for an entry."""
    if mode == "ECB":
        return encryptECB(key, plaintext)
    return encryptCBC(key, plaintext)

def buildVault(user):
    """Create the vault the 'cloud' stores for one user."""
    key = deriveKey(user["master_password"], user["username"], user["iterations"])
    entries = []
    for entry in user["entries"]:
        entries.append({
            "url": entry["url"],  # unencrypted metadata
            "login": encrypt(key, entry["login"], entry["mode"]),
            "password": encrypt(key, entry["password"], entry["mode"]),
        })
    return {
        "username": user["username"],
        "iterations": user["iterations"],  # stored right next to the vault
        "auth_hash": deriveAuthHash(key, user["master_password"]),  # server checks this at login
        "entries": entries,
    }


def main():
    vaults = [buildVault(user) for user in USERS]
    os.makedirs("data", exist_ok=True)
    with open("data/vaults.json", "w") as f:
        json.dump(vaults, f, indent=2)
    print(f"Wrote {len(vaults)} vaults to data/vaults.json")


if __name__ == "__main__":
    main()