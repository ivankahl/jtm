use super::*;

// FIPS 180 test vectors for the message "abc".
const ABC_SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                          2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

#[test]
fn one_pass_gives_every_digest_of_the_known_vectors() {
    let mut digests = Digests::new();
    digests.update(b"a");
    digests.update(b"bc");
    let done = digests.finish();
    assert_eq!(done.size, 3);
    assert_eq!(done.hex(HashAlgorithm::Sha1), ABC_SHA1);
    assert_eq!(done.hex(HashAlgorithm::Sha256), ABC_SHA256);
    assert_eq!(done.hex(HashAlgorithm::Sha512), ABC_SHA512);
    assert_eq!(done.sha256(), ABC_SHA256);
}

#[test]
fn the_empty_input_has_the_known_digests_and_zero_size() {
    let done = Digests::new().finish();
    assert_eq!(done.size, 0);
    assert_eq!(
        done.hex(HashAlgorithm::Sha256),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn it_works_as_a_writer_so_a_stream_can_be_copied_through_it() {
    use std::io::Write;
    let mut digests = Digests::new();
    digests.write_all(b"abc").unwrap();
    assert_eq!(digests.finish().hex(HashAlgorithm::Sha256), ABC_SHA256);
}
