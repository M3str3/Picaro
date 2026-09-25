// Custom stub that reads the key from argv instead of embedding it.
// The packer does NOT embed the key: PAYLOAD_KEY_DEF is not referenced
// below, so the key only arrives at runtime via argv.
//
// Usage: ./out.exe <hex_key>

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <hex_key>", args[0]);
        std::process::exit(1);
    }
    let key_bytes = hex::decode(&args[1]).expect("invalid hex key");
    if key_bytes.len() != 32 {
        eprintln!("key must be 32 bytes (64 hex chars)");
        std::process::exit(1);
    }

    let ciphertext: Vec<u8> = $PAYLOAD_BYTES$.to_vec();
    let nonce = $PAYLOAD_NONCE_DEF$;

    // decrypt with chacha20poly1305::XChaCha20Poly1305
    // ... el usuario escribe esta parte ...

    println!("decrypted {} bytes", plaintext.len());
}
