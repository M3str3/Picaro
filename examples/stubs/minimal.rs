// Minimal custom stub. Prints the payload size, does nothing else.
fn main() {
    let payload = $PAYLOAD_BYTES$;
    let len = $PAYLOAD_LEN$;
    println!("payload: {} bytes ({} ciphertext)", len, payload.len());
}
