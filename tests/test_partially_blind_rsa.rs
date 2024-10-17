// tests/blind_signature_tests.rs

#![cfg(test)]

use blind_rsa_signatures::{Error, Hash, KeyPair, Options, PublicKey, SecretKey};
use rsa::{BigUint, PublicKeyParts};
use rand::rngs::ThreadRng;
use rsa::{RsaPrivateKey, RsaPublicKey};


#[test]
fn test_partially_blind_signature() -> Result<(), blind_rsa_signatures::Error> {
    let options = Options::default();
    let rng = &mut rand::thread_rng();

    // [SERVER]: Generate a RSA-2048 key pair
    let kp = KeyPair::generate(rng, 1024)?;

    let (pk, sk) = (kp.pk, kp.sk);

    // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
    let msg = b"test";
    let metadata = b"metadata";
    let blinding_result = pk.blind_with_metadata(rng, msg, metadata,true, &options)?;

    // [SERVER]: compute a signature for a blind message, to be sent to the client.
    let blind_sig = sk.blind_sign_with_metadata(rng, &blinding_result.blind_msg, metadata, &options)?;

    // [CLIENT]: later, redeem a signed blind message
    let _sig = pk.finalize_with_metadata(
        &blind_sig,
        &blinding_result.secret,
        blinding_result.msg_randomizer,
        &msg,
        metadata,
        &options,
    )?;
    Ok(())
}

#[test]
fn test_partially_blind_signature_test_vector1() -> Result<(), blind_rsa_signatures::Error>  {
    let options = Options::default();
    let mut rng: ThreadRng = rand::thread_rng();

    let p_hex = "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a332\
    4c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf616\
    8ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c5\
    5f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3";

    let q_hex = "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c6\
    0b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc4\
    9cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed01\
    00b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3";

    let d_hex = "4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc522154\
    94981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e305\
    1b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc\
    000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62\
    ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa\
    4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a1\
    8d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4\
    abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d";

    let e_hex = "010001";

    let n_hex = "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69\
    821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd5\
    5f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75\
    e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710\
    f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61b\
    c7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366\
    a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725\
    cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9";

    let msg_hex=  "";

    let metadata_hex =  "6d65746164617461";

    let eprime_hex =  "30581b1adab07ac00a5057e2986f37caaa68ae963ffbc4d36c16ea5f3\
    689d6f00db79a5bee56053adc53c8d0414d4b754b58c7cc4abef99d4f0d0b2e29\
    cbddf746c7d0f4ae2690d82a2757b088820c0d086a40d180b2524687060d768ad\
    5e431732102f4bc3572d97e01dcd6301368f255faae4606399f91fa913a6d699d\
    6ef1";

    let blind_msg_hex = "cfd613e27b8eb15ee0b1df0e1bdda7809a61a29e9b6e9f3ec7c3\
    45353437638e85593a7309467e36396b0515686fe87330b312b6f89df26dc1cc8\
    8dd222186ca0bfd4ffa0fd16a9749175f3255425eb299e1807b76235befa57b28\
    f50db02f5df76cf2f8bcb55c3e2d39d8c4b9a0439e71c5362f35f3db768a5865b\
    864fdf979bc48d4a29ae9e7c2ea259dc557503e2938b9c3080974bd86ad8b0daa\
    f1d103c31549dcf767798079f88833b579424ed5b3d700162136459dc29733256\
    f18ceb74ccf0bc542db8829ca5e0346ad3fe36654715a3686ceb69f73540efd20\
    530a59062c13880827607c68d00993b47ad6ba017b95dfc52e567c4bf65135072\
    b12a4";


    // Convert hex to BigUint
    let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).expect("Invalid hex for p");
    let q = BigUint::parse_bytes(q_hex.as_bytes(), 16).expect("Invalid hex for q");
    let d = BigUint::parse_bytes(d_hex.as_bytes(), 16).expect("Invalid hex for d");
    let e = BigUint::parse_bytes(e_hex.as_bytes(), 16).expect("Invalid hex for e");
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).expect("Invalid hex for n");
    let msg: &[u8] = &hex::decode(msg_hex).expect("Invalid hex for msg");
    let metadata: &[u8] = &hex::decode(metadata_hex).expect("Invalid hex for metadata");
    let eprime = BigUint::parse_bytes(eprime_hex.as_bytes(), 16).expect("Invalid hex for e_prime");
    let blind_msg = BigUint::parse_bytes(blind_msg_hex.as_bytes(), 16).expect("Invalid hex for blind_msg");

    // Create the RSA private key from components
    let private_key = RsaPrivateKey::from_components(n,e,d,vec![p, q]).map_err(|_| Error::InvalidKey)?;

    // Create the corresponding public key
    let public_key = RsaPublicKey::from(&private_key);

    let pk = PublicKey(public_key);
    let sk = SecretKey(private_key);

    
    let blinding_result = pk.blind_with_metadata(&mut rng, msg, metadata,true, &options)?;


    let pk_derived = PublicKey::derive_public_key(pk.n(), metadata, Hash::Sha384)?;
    assert_eq!(pk_derived.e(), &eprime);

    let blind_sig = sk.blind_sign_with_metadata(&mut rng, &blinding_result.blind_msg, metadata, &options)?;

    let _sig = pk.finalize_with_metadata(
        &blind_sig,
        &blinding_result.secret,
        blinding_result.msg_randomizer,
        &msg,
        metadata,
        &options,
    )?;

    Ok(())

}

#[test]
fn test_partially_blind_signature_test_vector2() -> Result<(), blind_rsa_signatures::Error>  {
    let options = Options::default();
    let mut rng: ThreadRng = rand::thread_rng();

    let p_hex = "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a332\
    4c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf616\
    8ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c5\
    5f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3";

    let q_hex = "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56f\
    a8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db\
    5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b\
    651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3";

    let d_hex = "4e21356983722aa1adedb084a483401c1127b781aac89eab103\
    e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b3\
    94e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddf\
    c000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96\
    ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d\
    58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258a\
    a346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e80\
    5e574d704649985b600fa0ced8e5427071d7049de";

    let e_hex = "010001";

    let n_hex = "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69\
    821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd5\
    5f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75\
    e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710\
    f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61b\
    c7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366\
    a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725\
    cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9";

    let msg_hex=  "68656c6c6f20776f726c64";

    let metadata_hex =  "";

    let eprime_hex =  "2ed579fcdf2d328ebc686c52ccaec247018832acd530a2ac72c0ec2b9\
    2db5d6bd578e91b6341c1021142b45b9e6e5bf031f3dd62226ec4a0f9ef99e45d\
    d9ccd60aa60a0c59aac271a8caf9ee68a9d9ff281367dae09d588d3c7bca7f18d\
    e48b6981bbc729c4925c65e4b2a7f054facbb7e5fc6e4c6c10110c62ef0b94eec\
    397b";

    let blind_msg_hex = "cfd613e27b8eb15ee0b1df0e1bdda7809a61a29e9b6e9f3ec7c3\
    45353437638e85593a7309467e36396b0515686fe87330b312b6f89df26dc1cc8\
    8dd222186ca0bfd4ffa0fd16a9749175f3255425eb299e1807b76235befa57b28\
    f50db02f5df76cf2f8bcb55c3e2d39d8c4b9a0439e71c5362f35f3db768a5865b\
    864fdf979bc48d4a29ae9e7c2ea259dc557503e2938b9c3080974bd86ad8b0daa\
    f1d103c31549dcf767798079f88833b579424ed5b3d700162136459dc29733256\
    f18ceb74ccf0bc542db8829ca5e0346ad3fe36654715a3686ceb69f73540efd20\
    530a59062c13880827607c68d00993b47ad6ba017b95dfc52e567c4bf65135072\
    b12a4";


    // Convert hex to BigUint
    let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).expect("Invalid hex for p");
    let q = BigUint::parse_bytes(q_hex.as_bytes(), 16).expect("Invalid hex for q");
    let d = BigUint::parse_bytes(d_hex.as_bytes(), 16).expect("Invalid hex for d");
    let e = BigUint::parse_bytes(e_hex.as_bytes(), 16).expect("Invalid hex for e");
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).expect("Invalid hex for n");
    let msg: &[u8] = &hex::decode(msg_hex).expect("Invalid hex for msg");
    let metadata: &[u8] = &hex::decode(metadata_hex).expect("Invalid hex for metadata");
    let eprime = BigUint::parse_bytes(eprime_hex.as_bytes(), 16).expect("Invalid hex for e_prime");
    let blind_msg = BigUint::parse_bytes(blind_msg_hex.as_bytes(), 16).expect("Invalid hex for blind_msg");

    // Create the RSA private key from components
    let private_key = RsaPrivateKey::from_components(n,e,d,vec![p, q]).map_err(|_| Error::InvalidKey)?;

    // Create the corresponding public key
    let public_key = RsaPublicKey::from(&private_key);

    let pk = PublicKey(public_key);
    let sk = SecretKey(private_key);

    
    let blinding_result = pk.blind_with_metadata(&mut rng, msg, metadata,true, &options)?;


    let pk_derived = PublicKey::derive_public_key(pk.n(), metadata, Hash::Sha384)?;
    assert_eq!(pk_derived.e(), &eprime);

    let blind_sig = sk.blind_sign_with_metadata(&mut rng, &blinding_result.blind_msg, metadata, &options)?;

    let _sig = pk.finalize_with_metadata(
        &blind_sig,
        &blinding_result.secret,
        blinding_result.msg_randomizer,
        &msg,
        metadata,
        &options,
    )?;

    Ok(())

}

#[test]
fn test_partially_blind_signature_test_vector3() -> Result<(), blind_rsa_signatures::Error>  {
    let options = Options::default();
    let mut rng: ThreadRng = rand::thread_rng();

    let p_hex = "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a332\
    4c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf616\
    8ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c5\
    5f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3";

    let q_hex = "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56f\
    a8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db\
    5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b\
    651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3";

    let d_hex = "4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc522154\
    94981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e305\
    1b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc\
    000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62\
    ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa\
    4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a1\
    8d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4\
    abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d";

    let e_hex = "010001";

    let n_hex = "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd\
    7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049\
    bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f3\
    30a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe\
    03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c3180\
    81fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258a\
    b705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39a\
    e371b2b5dc1dafcb19d6fae9";

    let msg_hex=  "";

    let metadata_hex =  "6d65746164617461";

    let eprime_hex =  "30581b1adab07ac00a5057e2986f37caaa68ae963ffbc4d36c16ea5f3\
    689d6f00db79a5bee56053adc53c8d0414d4b754b58c7cc4abef99d4f0d0b2e29\
    cbddf746c7d0f4ae2690d82a2757b088820c0d086a40d180b2524687060d768ad\
    5e431732102f4bc3572d97e01dcd6301368f255faae4606399f91fa913a6d699d\
    6ef1";

    let blind_msg_hex = "cfd613e27b8eb15ee0b1df0e1bdda7809a61a29e9b6e9f3ec7c3\
    45353437638e85593a7309467e36396b0515686fe87330b312b6f89df26dc1cc8\
    8dd222186ca0bfd4ffa0fd16a9749175f3255425eb299e1807b76235befa57b28\
    f50db02f5df76cf2f8bcb55c3e2d39d8c4b9a0439e71c5362f35f3db768a5865b\
    864fdf979bc48d4a29ae9e7c2ea259dc557503e2938b9c3080974bd86ad8b0daa\
    f1d103c31549dcf767798079f88833b579424ed5b3d700162136459dc29733256\
    f18ceb74ccf0bc542db8829ca5e0346ad3fe36654715a3686ceb69f73540efd20\
    530a59062c13880827607c68d00993b47ad6ba017b95dfc52e567c4bf65135072\
    b12a4";


    // Convert hex to BigUint
    let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).expect("Invalid hex for p");
    let q = BigUint::parse_bytes(q_hex.as_bytes(), 16).expect("Invalid hex for q");
    let d = BigUint::parse_bytes(d_hex.as_bytes(), 16).expect("Invalid hex for d");
    let e = BigUint::parse_bytes(e_hex.as_bytes(), 16).expect("Invalid hex for e");
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).expect("Invalid hex for n");
    let msg: &[u8] = &hex::decode(msg_hex).expect("Invalid hex for msg");
    let metadata: &[u8] = &hex::decode(metadata_hex).expect("Invalid hex for metadata");
    let eprime = BigUint::parse_bytes(eprime_hex.as_bytes(), 16).expect("Invalid hex for e_prime");
    let blind_msg = BigUint::parse_bytes(blind_msg_hex.as_bytes(), 16).expect("Invalid hex for blind_msg");

    // Create the RSA private key from components
    let private_key = RsaPrivateKey::from_components(n,e,d,vec![p, q]).map_err(|_| Error::InvalidKey)?;

    // Create the corresponding public key
    let public_key = RsaPublicKey::from(&private_key);

    let pk = PublicKey(public_key);
    let sk = SecretKey(private_key);

    
    let blinding_result = pk.blind_with_metadata(&mut rng, msg, metadata,true, &options)?;


    let pk_derived = PublicKey::derive_public_key(pk.n(), metadata, Hash::Sha384)?;
    assert_eq!(pk_derived.e(), &eprime);

    let blind_sig = sk.blind_sign_with_metadata(&mut rng, &blinding_result.blind_msg, metadata, &options)?;

    let _sig = pk.finalize_with_metadata(
        &blind_sig,
        &blinding_result.secret,
        blinding_result.msg_randomizer,
        &msg,
        metadata,
        &options,
    )?;

    Ok(())

}

#[test]
fn test_partially_blind_signature_test_vector4() -> Result<(), blind_rsa_signatures::Error>  {
    let options = Options::default();
    let mut rng: ThreadRng = rand::thread_rng();

    let p_hex = "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a332\
    4c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf616\
    8ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c5\
    5f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3";

    let q_hex = "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56f\
    a8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db\
    5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b\
    651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3";

    let d_hex = "4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc522154\
    94981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e305\
    1b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc\
    000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62\
    ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa\
    4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a1\
    8d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4\
    abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d";

    let e_hex = "010001";

    let n_hex = "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69\
    821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd5\
    5f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75\
    e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710\
    f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61b\
    c7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366\
    a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725\
    cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9";

    let msg_hex=  "";

    let metadata_hex =  "";

    let eprime_hex =  "2ed579fcdf2d328ebc686c52ccaec247018832acd530a2ac72c0ec2b9\
    2db5d6bd578e91b6341c1021142b45b9e6e5bf031f3dd62226ec4a0f9ef99e45d\
    d9ccd60aa60a0c59aac271a8caf9ee68a9d9ff281367dae09d588d3c7bca7f18d\
    e48b6981bbc729c4925c65e4b2a7f054facbb7e5fc6e4c6c10110c62ef0b94eec\
    397b";

    let blind_msg_hex = "cfd613e27b8eb15ee0b1df0e1bdda7809a61a29e9b6e9f3ec7c3\
    45353437638e85593a7309467e36396b0515686fe87330b312b6f89df26dc1cc8\
    8dd222186ca0bfd4ffa0fd16a9749175f3255425eb299e1807b76235befa57b28\
    f50db02f5df76cf2f8bcb55c3e2d39d8c4b9a0439e71c5362f35f3db768a5865b\
    864fdf979bc48d4a29ae9e7c2ea259dc557503e2938b9c3080974bd86ad8b0daa\
    f1d103c31549dcf767798079f88833b579424ed5b3d700162136459dc29733256\
    f18ceb74ccf0bc542db8829ca5e0346ad3fe36654715a3686ceb69f73540efd20\
    530a59062c13880827607c68d00993b47ad6ba017b95dfc52e567c4bf65135072\
    b12a4";


    // Convert hex to BigUint
    let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).expect("Invalid hex for p");
    let q = BigUint::parse_bytes(q_hex.as_bytes(), 16).expect("Invalid hex for q");
    let d = BigUint::parse_bytes(d_hex.as_bytes(), 16).expect("Invalid hex for d");
    let e = BigUint::parse_bytes(e_hex.as_bytes(), 16).expect("Invalid hex for e");
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).expect("Invalid hex for n");
    let msg: &[u8] = &hex::decode(msg_hex).expect("Invalid hex for msg");
    let metadata: &[u8] = &hex::decode(metadata_hex).expect("Invalid hex for metadata");
    let eprime = BigUint::parse_bytes(eprime_hex.as_bytes(), 16).expect("Invalid hex for e_prime");
    let blind_msg = BigUint::parse_bytes(blind_msg_hex.as_bytes(), 16).expect("Invalid hex for blind_msg");

    // Create the RSA private key from components
    let private_key = RsaPrivateKey::from_components(n,e,d,vec![p, q]).map_err(|_| Error::InvalidKey)?;

    // Create the corresponding public key
    let public_key = RsaPublicKey::from(&private_key);

    let pk = PublicKey(public_key);
    let sk = SecretKey(private_key);

    
    let blinding_result = pk.blind_with_metadata(&mut rng, msg, metadata,true, &options)?;


    let pk_derived = PublicKey::derive_public_key(pk.n(), metadata, Hash::Sha384)?;
    assert_eq!(pk_derived.e(), &eprime);

    let blind_sig = sk.blind_sign_with_metadata(&mut rng, &blinding_result.blind_msg, metadata, &options)?;

    let _sig = pk.finalize_with_metadata(
        &blind_sig,
        &blinding_result.secret,
        blinding_result.msg_randomizer,
        &msg,
        metadata,
        &options,
    )?;

    Ok(())

}
