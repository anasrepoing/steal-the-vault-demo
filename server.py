import hmac
import json
import os
import secrets

from flask import Flask, jsonify, request

# the cloud storage file made by generate_vaults.py
VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "vaults.json")

# fake backup credential the attacker steals
BACKUP_KEY = "devops-backup-key-123"

app = Flask(__name__)
sessions = {}  # token -> username, in memory only

def loadVaults():
    """Read the stored vaults and look them up by username."""
    with open(VAULT_FILE) as f:
        return {vault["username"]: vault for vault in json.load(f)}

@app.get("/iterations/<username>")
def getIterations(username):
    """Send the iteration count so the client can derive the key."""
    vault = loadVaults().get(username)
    if vault is None:
        return jsonify({"error": "no such user"}), 404
    return jsonify({"iterations": vault["iterations"]})

@app.post("/login")
def login():
    """Check the client's auth hash and hand back a session token."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    auth_hash = body.get("auth_hash", "")

    vault = loadVaults().get(username)
    # constant-time compare, timing doesn't leak how close a guess was
    if vault is None or not hmac.compare_digest(vault["auth_hash"], auth_hash):
        return jsonify({"error": "bad username or password"}), 401

    token = secrets.token_hex(16)  # 16 random bytes as hex
    sessions[token] = username
    return jsonify({"token": token})

@app.get("/vault")
def getVault():
    """Give a logged-in user their own vault, still encrypted."""
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    username = sessions.get(token)
    if username is None:
        return jsonify({"error": "not logged in"}), 401

    vault = dict(loadVaults()[username])
    vault.pop("auth_hash")  # client doesn't need this back
    return jsonify(vault)

@app.get("/internal/backup")
def getBackup():
    """Give EVERY vault to anyone holding the backup key."""
    if request.headers.get("X-Backup-Key") != BACKUP_KEY:
        return jsonify({"error": "forbidden"}), 403
    with open(VAULT_FILE) as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)  # localhost only