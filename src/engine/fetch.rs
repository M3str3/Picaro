//! In-memory fetch of the input payload over HTTP(S).
//!
//! The input PE is fetched over HTTP(S) and read directly into memory; it is
//! never written to disk. A size cap bounds memory use if a URL unexpectedly
//! serves a very large resource.

use std::io::Read;

use crate::error::{PackerError, Result};

/// Maximum input payload size we will fetch, in bytes (64 MiB).
///
/// PE payloads are far smaller than this; the cap exists only to bound memory
/// use if a URL serves something unexpected.
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Fetches `url` over HTTP(S) and returns its body as bytes, without writing
/// to disk.
pub fn fetch_url(url: &str) -> Result<Vec<u8>> {
    fetch_url_limited(url, MAX_INPUT_BYTES)
}

/// [`fetch_url`] with an explicit size cap (kept separate for tests).
fn fetch_url_limited(url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(60))
        .build();

    let response = agent
        .get(url)
        .call()
        .map_err(|source| PackerError::FetchInput {
            url: url.to_string(),
            source: Box::new(source),
        })?;

    // `ureq` already errors on 4xx/5xx, but guard again for a clear message.
    if response.status() >= 400 {
        return Err(PackerError::FetchInput {
            url: url.to_string(),
            source: Box::new(std::io::Error::other(format!(
                "server returned HTTP {}",
                response.status()
            ))),
        });
    }

    let mut body = Vec::new();
    response
        .into_reader()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|source| PackerError::FetchInput {
            url: url.to_string(),
            source: Box::new(source),
        })?;

    if body.len() > max_bytes {
        return Err(PackerError::Validation(format!(
            "input payload exceeds the {max_bytes} byte fetch limit"
        )));
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Serves `body` once on an ephemeral local port, returning its URL.
    fn serve_once(body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            // `write` results are intentionally ignored: the client may stop
            // reading early (e.g. when testing the size cap).
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(body);
        });

        format!("http://{addr}/payload.exe")
    }

    #[test]
    fn fetches_body_from_local_http_server() {
        let body: &'static [u8] = b"MZ\x90\x00fake-pe";
        let url = serve_once(body);
        assert_eq!(fetch_url(&url).expect("fetch"), body);
    }

    #[test]
    fn enforces_size_limit() {
        let body: &'static [u8] = b"1234567890"; // 10 bytes
        let url = serve_once(body);
        let err = fetch_url_limited(&url, 4).expect_err("must exceed the limit");
        assert!(err.to_string().contains("fetch limit"), "unclear: {err}");
    }
}
