# generate_vaults.py notes

- Makes fake vaults -> data/vaults.json (the "cloud storage" that gets stolen later)
- USERS = answer key, master pwds never saved to output
- deriveKey: PBKDF2, email as salt, iterations = attacker cost per guess (Scarlata)
- deriveAuthHash, 1 more PBKDF2 round on key w/ master pwd as salt -> login hash (Scarlata)
- pad/toText: AES needs 16-byte blocks; base64 so bytes fit in JSON
- ECB = same pwd -> same ciphertext -> reuse visible. CBC = random IV, no leak
- URLs + iteration count left unencrypted on purpose: iteration count unencrypted (Scarlata), unencrypted metadata in 2022 breach (Gentles)
- We are modeling the old breach-era LastPass (today's LastPass encrypts URLs per Scarlata)
- ECB only shows reuse in one person's vault since everyone has their own key
- Iteration counts: 600,000 current default (Scarlata); 500/5000/100,100 history [need source eventually]
- ECB reuse leak [need source eventually]

# server.py notes

- Flask mock cloud on localhost, serves data/vaults.json
- Server stores login hash, checks it matches at login
- /iterations gives client the count before it derives the key
- /login checks auth hash -> token, never sees master pwd
- /vault needs token, returns only your own encrypted vault
- /internal/backup gives all vaults w/ backup key, stand-in for stolen backup keys

# client.py notes

- iterations -> deriveKey -> deriveAuthHash -> login -> fetch vault -> decrypt locally

# steal.py notes

- Stolen backup key -> every vault saved to loot/
- Sorts users by iterations, flags ECB reuse