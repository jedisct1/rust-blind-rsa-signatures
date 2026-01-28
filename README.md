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

For convenience, you can define a type alias:

```rust
use blind_rsa_signatures::{KeyPair, PublicKey, SecretKey, Sha384, PSS, Randomized};

type MyKeyPair = KeyPair<Sha384, PSS, Randomized>;
type MyPublicKey = PublicKey<Sha384, PSS, Randomized>;
type MySecretKey = SecretKey<Sha384, PSS, Randomized>;
```

This crate also includes utility functions to import and export keys.

## For other languages

* [Zig](https://github.com/jedisct1/zig-rsa-blind-signatures)
* [C](https://github.com/jedisct1/blind-rsa-signatures)
* [Go](https://pkg.go.dev/github.com/cloudflare/circl/blindsign/blindrsa)
* [TypeScript](https://github.com/cloudflare/blindrsa-ts)
