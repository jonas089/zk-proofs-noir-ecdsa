use dep::std;

fn main(message_hash : [u8;32], pub_key_x : [u8;32], pub_key_y : [u8;32], signature : [u8;64]) {
    // hash the message again (this happens when we generate a deterministic signature)
    // the reason we do this is to ensure persistent input message length (always 32 bytes)
    let message_hash_2 = std::hash::sha256(message_hash);

    let valid_signature = std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, message_hash_2);
    assert(valid_signature);
}

#[test]
fn test_main() {
    main(
[223, 253, 96, 33, 187, 43, 213, 176, 175, 103, 98, 144, 128, 158, 195, 165, 49, 145, 221, 129, 199, 247, 10, 75, 40, 104, 138, 54, 33, 130, 152, 111],
[77, 154, 126, 232, 196, 225, 168, 59, 92, 209, 131, 12, 75, 100, 207, 199, 5, 43, 99, 228, 204, 68, 6, 215, 158, 218, 115, 138, 189, 163, 55, 245],
[16, 228, 74, 23, 195, 86, 207, 3, 197, 97, 183, 204, 88, 193, 180, 218, 193, 183, 83, 215, 24, 137, 139, 93, 43, 143, 42, 151, 214, 102, 243, 75],
[230, 120, 141, 193, 123, 240, 107, 68, 229, 28, 43, 118, 121, 95, 209, 71, 158, 89, 0, 244, 242, 87, 223, 154, 39, 236, 163, 8, 122, 66, 225, 21, 38, 48, 182, 148, 244, 248, 85, 165, 224, 231, 211, 166, 42, 170, 118, 153, 140, 184, 20, 128, 195, 182, 233, 102, 181, 197, 208, 199, 240, 171, 150, 87]
    );
}
