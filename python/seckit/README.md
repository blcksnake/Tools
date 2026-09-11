# SecKit

SecKit is a desktop security and cryptography toolkit by BLCKSNAKE. It provides local tools for generating credentials and keys, hashing data, working with JWTs, and creating or inspecting X.509 certificates.

## Features

- Strong password and secure username generation
- Random hex, Base64, Base64URL, and URL-safe tokens
- Text and file hashing with constant-time verification
- JWT encoding, decoding, and signature verification
- RSA, EC, Ed25519, and OpenSSH key-pair generation
- X.509 root CAs, CSRs, certificate signing, and verification
- Certificate inspection, including SANs, fingerprints, and expiration
- Dark, light, and system appearance modes
- Optional anonymous usage analytics

## Requirements

- Python 3
- `customtkinter`
- `cryptography`
- `PyJWT`

Install the required packages:

```shell
pip install customtkinter cryptography PyJWT
```

Run from source:

```shell
python seckit.py
```

## Safe usage

- Use SecKit only with systems, certificates, keys, and data you own or are authorized to manage.
- Treat generated passwords, tokens, private keys, passphrases, and CA material as secrets. Store them securely and clear clipboard contents after copying them.
- Decoding a JWT does not prove it is authentic. Use signature verification before trusting its claims.
- Hashing is not encryption and cannot restore the original input. Keep backups before processing important files.
- Protect root CA private keys carefully. A compromised CA key can be used to issue certificates that appear trusted.
- Self-signed certificates are intended mainly for development, testing, or controlled internal environments unless they are deliberately installed into a managed trust system.
- Review certificate names, SANs, expiration dates, and key types before deploying generated certificates.
- Cryptographic operations run locally. Anonymous analytics are optional and can be disabled from the About panel.

## License

MIT

## Resources

- https://github.com/blcksnake/Tools/tree/main/python/seckit
- https://blcksnake.com
