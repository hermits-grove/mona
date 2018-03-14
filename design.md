# Mona: A transparently secure secret manager

## THINGS TO LOOK INTO:
- Password strength estimation: https://github.com/tsyrogit/zxcvbn-c
## Metadata File
For each encrypted file {encrypted_file_path} we have {encrypted_file_path}.json which
describes how {encrypted_file_path} was encrypted.

_Metadata Format:_

```toml
#<garble>.toml
#  - accompanying file to the encrypted file with path: <garble>
version = "0.0.1"          # mona client version number

[plaintext]
min_bits = 1024            # plaintext is padded to this min bit length

[pbkdf2]
algo = "Sha256"            # digest algo used by pbkdf2
iters = 1000000            # iterations done by pbkdf2
salt = "4ZHmDMPkbOfpnKCh"  # salt given to pbkdf2

[aead]
algo = "ChaCha20-Poly1305" # AEAD block cipher algo
nonce = "tL8UZ79l0wWtzmfj" # nonce which was used to encrypt matching file
keylen = 256               # length of secret key which was used to encrypt

[paranoid]
# Extra security for the *extra* paranoid
#
# These options are here to provide an attempt at future proofing encrypted data
# against unknown attacks on current crypto algorithms.
#
# ! Given current understanding of crypto these are NOT REQUIRED FOR A SECURE SYSTEM.

# Simple Multiple Encryption is done using the method described by Bruce Schneier:
# - generate a random <pad> of the same size of the plaintext
# - XOR the plaintext with the <pad> resulting in a <ciphertext1>.
# - Encrypt the <pad> with <cipher1> and key1 -> <ciphertext2>
# - encrypt <ciphertext1> with <cipher1> and key2 -> <ciphertext3>
# - ciphertext4 = <ciphertext2>|<ciphertext3>
# A cryptanalyst must break both ciphers to get any information
# This will, however, have the drawback of making the ciphertext twice as long as the original plaintext.
# 
# This process can be repeated with a third cipher by treating <ciphertext4> as plaintext and going through the same process again
simple_multiple_encryption = "TBD" # not implemented yet

# Cascading Encryption:
# ciphertext = cipher<N>(key<N>, cipher<N-1>(key<N-1>..cipher1(key1, plaintext)...))
# -- nesting different ciphers all with *unique* keys
cascading_encryption = "TBD"       # not implemented yet
```

## AEAD nonce
$MONA_HOME/burned_nonces file contains a list of nonces which have
previously been used to encrypt files.

A new nonce must be checked against this list to verify it has never been used to
encrypt a file.

## Manifest
Encrypted file containing lookup information about stored secrets.

### Manifest Format
A list of entries stored in git-db with their associated data

```toml
[[entries]]
path = ["misc", "new.ycombinator.com"]
tags = ["hacker", "news", "social", "ycombinator"]
garbled_path = ["lj01g7OD8g30F6X9"]

[[entries]]
path = ["misc", "www.facebook.com"]
tags = ["facebook", "social"]
garbled_path = ["lj01g7OD8g30F6X9"]

[[entries]]
path = ["misc", "mail.protonmail.com"]
tags = ["mail", "protonmail", "social"]
garbled_path = ["lj01g7OD8g30F6X9"]

[[entries]]
path = ["work", "mona", "design.md"]
tags = []
garbled_path = ["lj01g7OD8g30F6X9"]
```

## Thoughts on secure browser crypto
- mobile app stores offline cache of website ssl certificate.

1. user visits https://mona.com/web (enforce ssl)
2. user is told to take out his mobile phone and follow untrusted client instructions
3. user is on app:
   - user is given instructions on how to pull up fingerprint
   - app has OCR feature to extract fingerprint -> compares against cache
   - if different: warn user that this connection has been MITM'ed
   - if matches: tell user the connection is secure
   - TAI: we don't really need authenticity, we need content integrity

4. if user has internet access from phone:
   - website generates a private/public key pair
   - website encodes public key in qr code
   - website displays qr code and starts polling backend for encrypted metadata file
   - user uses mobile app to take picture of qr code, decodes public key
   - app decrypts metadata and re-encrypts metadata file using public key
   - app sends encrypted metadata to backend
   - website polling finds encrypted metadata and fetches it
   - website decrypts metadata using private key
   - website shows metadata and allows user to search for the secret they need
   - user selects secret, website encodes secret identifier in QR code
   - mobile app is used to decode QR code, and as before it decrypts and re-encrypts secret using stored public key, posts to backend
   - website polls for secret and fetches and decrypts it.

5. if user has no internet access from phone, warn user about possibility of keylongers, if user agrees to accept the risk, prompt user for master passphrase and have the website clone the git repository into memory and decrypt things as needed client side.

## TAI
- synchronizing access to $MONA_HOME, this is custom to each client


## GIT DB

_Encrypted key value store built on top of Git._

```
key: a user chosen file path
value: binary blob
```

A blob is stored on disk by two files with the same garbled path prefix

```
<garble>/<garble>      # encrypted data
<garble>/<garble>.toml # instructions how to decrypt data
```

```
git_db_root/
├── .git/...
├── <garble>/
│   ├── <garble>      # The encrypted data
│   └── <garble>.toml # Plaintext TOML file with encryption details
│...
```

A mapping from the key (the user provided lookup path) and the garbled path is stored in an encrypted manifest file in the root directory

```
git_db_root/
├── .git/...
├── manifest         # encrypted manifest
├── manifest.toml    # plaintext manifest encryption details
│...
```

Each entry in the Git DB has an entry in the manifest that looks similar to:

```toml
[[entries]]
path = ["path", "to", "file.txt"]    # normalized form of 'path/to/file.txt'
tags = ["optional", "tags", "for", "queries"]
garbled_path = ["<garble>", "<garble>"] # randomly generated path
```

_how git db looks up a file:_
1. git-db decrypts manifest with instrucrions from "manifest.toml"
2. scan entries for a path matching their <lookup path>
3. if match found, extract matching <garbled path>.
5. git-db decrypts the <garbled path> file with instructions from <garbled path>.toml

_notes:_
- garbled path is required to hide information leaked by structure of repository
- keys are derived using some varient of kdf(pass, salt). Per blob salt will give us
  a unique secret key for each encrypted blob ==> sad days for NSA
- nothing is stopping users from using different passwords to encrypt seperate files

