# Mona: A transparently secure secret manager

binary to ascii encoding scheme: Base32 (we need filename and url safe strings)

## Encrypt a secret:
INPUTS:
- passphrase: u8 array
- plaintext_secret: u8 array
- filename: u8 array
- metadata: see Metadata Format

OUTPUTS:
- Metadata is json encoded and written to {filename}.json
- Encrypted file is written to {filename}

STEPS:
```
encoded_metadata : [u8] = json_encode(metadata)
write_file(filename + ".json", encoded_metadata)

assert metadata.paranoid.key_derivation_iterations >= 1

key : [u8] = passphrase
for key_i in 0..metadata.paranoid.key_derivation_iterations:
    for key_algo in metadata.key_derivation:
      key = key_algo.derive(key)

padded_plaintext : [u8] = allocate(metadata.plaintext_padding * 2 + plaintext.length);
padded_plaintext[0..metadata.plaintext_padding] = random_bytes(num_bytes=metadata.plaintext_padding)
padded_plaintext[metadata.plaintext_padding..plaintext.length] = plaintext;
padded_plaintext[plaintext.length + metadata.plaintext_padding..] = random_bytes(num_bytes=metadata.plaintext_padding);

assert metadata.paranoid.encrypt_iterations >= 1

ciphertext : [u8] = padded_plaintext
for encrypt_i in 0..metadata.paranoid.encrypt_iterations:
    for encrypt_algo in metadata.encrypt:
        ciphertext = encrypt_algo.encrypt(key, ciphertext)

write_file(filename, ciphertext)
```

## Metadata File
For each encrypted file {encrypted_file_path} we have {encrypted_file_path}.json which
describes how {encrypted_file_path} was encrypted.

### Metadata Format 
We use JSON since a well tested JSON parser exists for most languages.
``` javascript
# {encrypted_file_path}.json
{
  "key_derivation": [
    { "name": "pbkdf2":
      "algo": "<algo>"    # one of {"Sha256"}:            algorithm used by pbkdf2
      "iters": <iters>,   # positive i32:       iterations argument to pbkdf2
      "salt": "<salt>",   # base32 encoded string:        salt argument to pbkdf2
    },
	# ... more derivation algos here iterations here
  ],
  "encrypt": [
    "aead": {
      "nonce": "<nonce>", # base32 encoded string:        nonce used by aead
      "algo": "<algo>",   # one of {"ChaCha20-Poly1305"}: algorithm used by aead
    },
    "<second_encryption_iteration>": {
      "nonce": "<nonce>", # base32 encoded string:        nonce used by aead
      "algo": "<algo>",   # one of {"ChaCha20-Poly1305"}: algorithm used by aead
    }
  ]
  "paranoid": {
    # Extra security for the *extra* paranoid
    #
    # These options are here to provide an attempt at future proofing encrypted data
	# against unknown attacks on current crypto algorithms.
	#
	# ! These features are not required to have a secure system given our current
	# understanding of cryptography
	"plaintext_padding": <padding>, # positive i32: surround plaintext with n random bytes on both sides
	"key_derivation_iters": <iters>, # positive i32: repeat key derivation <iter> number of times
	"encrypt_iters": <iters>, # positive i32: repeat encryption <iter> number of times
  }
}
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

## TAI
- synchronizing access to $MONA_HOME, this is custom to each client
