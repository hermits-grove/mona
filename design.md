# Mona: A transparently secure secret manager

# Support for Multiple Encryption:
https://en.wikipedia.org/wiki/Multiple_encryption


binary to ascii encoding scheme: Base32 (we need filename and url safe strings)

## Encrypt a secret:
INPUTS:
- master_passphrase: u8 array
- plaintext_secret: u8 array
- ciphertext_filepath: String
- metadata: see Metadata Format

OUTPUTS:
- Metadata is json encoded and written to {filename}.json
- Encrypted file is written to {filename}

Pseudocode
``` rust

# ASSUME
# metadata.kdf.name == "pbkdf2"
# metadata.kdf.algo == "
key : [u8] = passphrase
for key_i in 0..metadata.paranoid.key_derivation_iterations:
    for key_algo in metadata.key_derivation:
        key = key_algo.derive(key)

padded_plaintext : [u8] = allocate(metadata.plaintext_padding * 2 + plaintext.length);
padded_plaintext[0..metadata.plaintext_padding] = random_bytes(num_bytes=metadata.plaintext_padding)
padded_plaintext[metadata.plaintext_padding..plaintext.length] = plaintext;
padded_plaintext[plaintext.length + metadata.plaintext_padding..] = random_bytes(num_bytes=metadata.plaintext_padding);

assert metadata.paranoid.encrypt_iterations >= 1
encoded_metadata : [u8] = toml_encode(metadata)


ciphertext : [u8] = padded_plaintext
for encrypt_i in 0..metadata.paranoid.encrypt_iterations:
    for encrypt_algo in metadata.encrypt:
        ciphertext = encrypt_algo.encrypt(key, ciphertext)

write_file(filename + ".json", encoded_metadata)
write_file(filename, ciphertext)
```

## Metadata File
For each encrypted file {encrypted_file_path} we have {encrypted_file_path}.json which
describes how {encrypted_file_path} was encrypted.

### Metadata Format 

```toml
# encrypted/file.toml
[ mona ]
version = "0.0.1"
encoding = "base64url"

[ plaintext ] # Modifications to plaintext prior to encrypting
# if plaintext is smaller than min_bits, plaintext will be extended to
# at least min_bits with random bytes
#
#     padded_plaintext : pad_len | random_bytes | plaintext
#     pad_len : i32 = max(0, ceil((min_bits - plaintext.len() * 8) / 8.))
#     random_bits : pad_len number of random bytes
#
# Total padded_plaintext length in bytes = 4 + pad_len + plaintext
#
# purpose is to hide length of short plaintext
min_bits = 1024

[ kdf ] # Key Derivation Function
name = "pbkdf2"
algo = "Sha256" # algorithm to be used by pbkdf2
iters = 100000  # positive i32: iterations argument to pbkdf2
salt = "<salt>" # base32 encoded string: salt argument to pbkdf2

[ encrypt ]
name = "aead"
algo = "ChaCha20-Poly1305" # string: name of cipher 
nonce = "<nonce>"          # base32 encoded string
keylength = 256            # positive i32: numbert of bits

[ paranoid ]
# Extra security for the *extra* paranoid
#
# These options are here to provide an attempt at future proofing encrypted data
# against unknown attacks on current crypto algorithms.
#
# ! These features are not required to have a secure system given our current
# understanding of cryptography
#
# TAI: what should go here?
```

## generating a nonce:
$MONA_HOME/burned_nonces file contains a list of base32 encoded nonces which have
previously been used to encrypt files.
A new nonce must be checked against this list to verify it has never been used to
encrypt a file.

### $MONA_HOME/burned_nonces
base32 encoded nonces seperated by newlines
e.g.
```
MFRGGZDBMJRWIYLCMNSGCYTDMRSXG===
ONSGUZR3NRQXGZDLNJTGC3DTMQ5WM===
...
```

### STEPS TO GENERATE A NONCE
1. Generate a random value (currently 96 bits)
2. Check that it does not exist in the `burned_nonces`
3. Add it to `burned_nonces`


## Manifest
Encrypted file containing lookup information about stored secrets.

### Manifest Format
We use JSON since a well tested JSON parser exists for most languages.

``` javascript
{
  "<path/to/secret>": {
    "type": "file",
    "tags": ["news.ycombinator.com", "hacker", "news", ...],
    "<client_name>": {
      # mona clients are free to add additional lookup data
    },
	"<client_name2>": {
      # ...
    }
  }
  "path/to": {
    "type": "dir",
    "tags": ["social"],
    # ...
  }
  "path": {
    "type": "dir",
    "tags": ["passwords"],
    ...
  }
  "path2": {
    "type": "dir",
    "tags": ["files"],
    ...
  }
}
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


