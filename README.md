[![GitHub CI](https://github.com/jedisct1/rust-blind-rsa-signatures/actions/workflows/ci.yml/badge.svg)](https://github.com/jedisct1/rust-blind-rsa-signatures/actions)
[![Docs.rs](https://docs.rs/blind-rsa-signatures/badge.svg)](https://docs.rs/blind-rsa-signatures/)
[![crates.io](https://img.shields.io/crates/v/blind-rsa-signatures.svg)](https://crates.io/crates/blind-rsa-signatures)

# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This is an implementation of the [RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html) (RFC 9474), based on [the Zig implementation](https://github.com/jedisct1/zig-rsa-blind-signatures).

## Protocol overview

A client asks a server to sign a message. The server receives the message, and returns the signature.

Using that `(message, signature)` pair, the client can locally compute a second, valid `(message', signature')` pair.

Anyone can verify that `(message', signature')` is valid for the server's public key, even though the server didn't see that pair before.
But no one besides the client can link `(message', signature')` to `(message, signature)`.

Using that scheme, a server can issue a token and verify that a client has a valid token, without being able to link both actions to the same client.

1. The client creates a random message, and blinds it with a random, secret factor.
2. The server receives the blind message, signs it and returns a blind signature.
3. From the blind signature, and knowing the secret factor, the client can locally compute a `(message, signature)` pair that can be verified using the server's public key.
4. Anyone, including the server, can thus later verify that `(message, signature)` is valid, without knowing when step 2 occurred.

The scheme was designed by David Chaum, and was originally implemented for anonymizing DigiCash transactions.

## Usage

```rust
use blind_rsa_signatures::{KeyPair, Sha384, PSS, Randomized, DefaultRng};

// [SERVER]: Generate a RSA-2048 key pair
let kp = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048)?;
let (pk, sk) = (kp.pk, kp.sk);

// [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
// The client must store the message and the secret.
let msg = b"test";
let blinding_result = pk.blind(&mut DefaultRng, msg)?;

// [SERVER]: compute a signature for a blind message, to be sent to the client.
// The client secret should not be sent to the server.
let blind_sig = sk.blind_sign(&blinding_result.blind_message)?;

// [CLIENT]: later, when the client wants to redeem a signed blind message,
// using the blinding secret, it can locally compute the signature of the
// original message.
// The client then owns a new valid (message, signature) pair, and the
// server cannot link it to a previous (blinded message, blind signature) pair.
// Note that the finalization function also verifies that the new signature
// is correct for the server public key.
let sig = pk.finalize(&blind_sig, &blinding_result, msg)?;

// [SERVER]: a non-blind signature can be verified using the server's public key.
pk.verify(&sig, blinding_result.msg_randomizer, msg)?;
```

## Configuration options

The key types take three compile-time parameters:

- Hash algorithm: `Sha256`, `Sha384`, `Sha512`
- Salt mode: `PSS` (with salt), `PSSZero` (without salt)
- Message preparation: `Randomized`, `Deterministic`

Pre-defined type aliases are available for all SHA-384 configurations:

| Variant                        | KeyPair                             | PublicKey                             | SecretKey                             |
| ------------------------------ | ----------------------------------- | ------------------------------------- | ------------------------------------- |
| PSS + Randomized (recommended) | `KeyPairSha384PSSRandomized`        | `PublicKeySha384PSSRandomized`        | `SecretKeySha384PSSRandomized`        |
| PSSZero + Randomized           | `KeyPairSha384PSSZeroRandomized`    | `PublicKeySha384PSSZeroRandomized`    | `SecretKeySha384PSSZeroRandomized`    |
| PSS + Deterministic            | `KeyPairSha384PSSDeterministic`     | `PublicKeySha384PSSDeterministic`     | `SecretKeySha384PSSDeterministic`     |
| PSSZero + Deterministic        | `KeyPairSha384PSSZeroDeterministic` | `PublicKeySha384PSSZeroDeterministic` | `SecretKeySha384PSSZeroDeterministic` |

For SHA-256 or SHA-512, use the generic types directly:

```rust
use blind_rsa_signatures::{KeyPair, Sha512, PSS, Randomized, DefaultRng};

let kp = KeyPair::<Sha512, PSS, Randomized>::generate(&mut DefaultRng, 2048)?;
```

## Key import/export

Keys can be imported and exported in DER, PEM, and SPKI formats:

```rust
use blind_rsa_signatures::PublicKeySha384PSSRandomized;

// Export
let der = pk.to_der()?;
let pem = pk.to_pem()?;
let spki = pk.to_spki()?;

// Import
let pk = PublicKeySha384PSSRandomized::from_der(&der)?;
let pk = PublicKeySha384PSSRandomized::from_pem(&pem)?;
let pk = PublicKeySha384PSSRandomized::from_spki(&spki)?;
```

## Partially Blind RSA Signatures

The `pbrsa` module implements Partially Blind RSA Signatures (IRTF CFRG draft), which allow a signer to bind signatures to public metadata while keeping the message content blind.

```rust
use blind_rsa_signatures::pbrsa::{PartiallyBlindKeyPair, DefaultRng};
use blind_rsa_signatures::{Sha384, PSS, Randomized};

// [SERVER]: Generate a key pair with safe primes (required for PBRSA)
let kp = PartiallyBlindKeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048)?;

// [SERVER]: Derive a key pair for specific metadata
let metadata = b"2024-01-15";
let derived_kp = kp.derive_key_pair_for_metadata(metadata)?;

// [CLIENT]: Blind a message with metadata
let msg = b"token-12345";
let blinding_result = derived_kp.pk.blind(&mut DefaultRng, msg, Some(metadata))?;

// [SERVER]: Sign the blinded message
let blind_sig = derived_kp.sk.blind_sign(&blinding_result.blind_message)?;

// [CLIENT]: Finalize to get the actual signature
let sig = derived_kp.pk.finalize(&blind_sig, &blinding_result, msg, Some(metadata))?;

// [ANYONE]: Verify the signature with metadata
derived_kp.pk.verify(&sig, blinding_result.msg_randomizer, msg, Some(metadata))?;
```

Key differences from standard blind RSA:
- Keys must use safe primes (p and q where (p-1)/2 and (q-1)/2 are also prime)
- Signatures are bound to public metadata
- Key derivation generates per-metadata key pairs

## For other languages

* [Zig](https://github.com/jedisct1/zig-blind-rsa-signatures)
* [C](https://github.com/jedisct1/c-blind-rsa-signatures)
* [Go](https://pkg.go.dev/github.com/cloudflare/circl/blindsign/blindrsa)
* [TypeScript](https://github.com/cloudflare/blindrsa-ts)
