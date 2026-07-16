# DEDSEC_ZEN

> **Extract saved passwords from Firefox, Zen, LibreWolf & more — no root required.**

A lightweight C++ tool that decrypts saved login credentials from Firefox-based browsers by reading the local `key4.db` + `logins.json` files. Works on any Linux desktop **without root privileges** — it reads your own browser profile, to which you already have access.

Ever locked yourself out of an account because Firefox "helpfully" autofilled a password you never actually memorized? Forgot the admin creds to that local dev server you set up 6 months ago? Need to migrate your 50+ saved logins to a password manager but Firefox's export is garbage? **This tool decrypts them all in one shot** — no master password needed, no root, no browser restarts, no clicking through 47 settings menus. Just execute and it dumps every saved username and password in plaintext.

Unlike GUI-based extractors that require you to open Firefox and manually export each login, DEDSEC Decryptor works directly on the raw database files. It reverse-engineers NSS (Network Security Services) — the same crypto engine that secures your browser — using the exact PBKDF2 + AES-256-CBC / 3DES-CBC decryption chain that Firefox itself uses. If Firefox can decrypt it, so can this.

![C++](https://img.shields.io/badge/C++-17-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Size](https://img.shields.io/badge/binary-73KB-lightgrey)

---

## Features

| Feature | Detail |
|---------|--------|
|  **Auto-detection** | Scans profiles for Firefox, Zen, LibreWolf, Waterfox, Floorp, Pulse |
|  **Dual cipher** | AES-256-CBC (newer) + DES-EDE3-CBC (legacy Firefox) |
|  **No root** | Reads your own `~/.mozilla` / `~/.zen` profile — no `sudo` |
|  **73 KB** | Tiny binary, compiles in seconds |

## Supported Browsers

| Browser | Profile Path | Status |
|---------|-------------|--------|
| Mozilla Firefox | `~/.mozilla/firefox/` | ✅ |
| Zen Browser | `~/.zen/` | ✅ |
| LibreWolf | `~/.librewolf/` | ✅ |
| Waterfox | `~/.waterfox/` | ✅ |
| Floorp | `~/.floorp/` | ✅ |
| Pulse Browser | `~/.pulse/` | ✅ |

---

##  Quick Start

### One-liner build & run (C++)

```bash
# Build
g++ -std=c++17 -O2 -o dedsec_decryptor dedsec_browser_decryptor.cpp -lsqlite3 -lcrypto -lpthread -ldl

# Static build
g++ -std=c++17 -O2 -static -o dedsec_decryptor dedsec_browser_decryptor.cpp -lsqlite3 -lcrypto -lzstd -lz -lpthread -ldl

# Run (auto-detects all browser profiles)
./dedsec_decryptor
```
---

## How It Works

Firefox-based browsers store passwords in two files inside your profile folder:

| File | Contents |
|------|----------|
| `logins.json` | AES/3DES-encrypted usernames & passwords |
| `key4.db` | SQLite database with the decryption key (NSS PKCS#11 softoken) |

### Decryption chain

```
key4.db (metaData.item1)  →  global_salt
        ↓ SHA-1
        password
        ↓ PBKDF2-HMAC-SHA256
        master key (decrypts nssPrivate.a11)
        ↓ AES-256/3DES-CBC
        decryption key
        ↓
logins.json (encryptedUsername/encryptedPassword)
        ↓ AES-256-CBC / 3DES-CBC
        plaintext credentials 
```

### NSS quirk

The AES IV in the PBES2 ASN.1 structure includes the ASN.1 **tag+length bytes** (`04 0e`) as part of the 16-byte IV — a non-standard NSS encoding discovered during development.

---

## Disclaimer

This tool is intended for **educational purposes and personal use only**. Only use it to recover **your own** passwords from **your own** browser profiles. Unauthorized access to others' data is illegal.

---

