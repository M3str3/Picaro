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

    // Read the declared length *before* consuming the response reader, so a
    // late reset can be told apart from a truncated body.
    let expected_len = response
        .header("Content-Length")
        .and_then(|v| v.trim().parse::<usize>().ok());

    let body = read_body(response.into_reader(), expected_len, max_bytes).map_err(|source| {
        PackerError::FetchInput {
            url: url.to_string(),
            source: Box::new(source),
        }
    })?;

    if body.len() > max_bytes {
        return Err(PackerError::Validation(format!(
            "input payload exceeds the {max_bytes} byte fetch limit"
        )));
    }

    Ok(body)
}

/// Reads `reader` to EOF, tolerating a connection reset that arrives *after*
/// the whole body was received.
///
/// A peer that closes without a clean FIN (common on Windows loopback, and
/// occasionally triggered by active AV) makes the OS surface `RST` as a
/// [`std::io::ErrorKind::ConnectionReset`]/`ConnectionAborted` read error, even
/// though every byte was already delivered. If `expected_len` bytes (the
/// `Content-Length`) were received, that trailing reset is not a failure.
fn read_body(
    reader: impl Read,
    expected_len: Option<usize>,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let result = reader.take(max_bytes as u64 + 1).read_to_end(&mut body);

    if let Err(error) = result {
        let complete = expected_len.is_some_and(|len| body.len() >= len);
        if !(complete && is_connection_reset(&error)) {
            return Err(error);
        }
    }

    Ok(body)
}

/// Whether `error` is a connection reset/abort (WSAECONNRESET 10054 /
/// WSAECONNABORTED 10053 on Windows).
fn is_connection_reset(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
    )
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
            // Drain the client's request *before* closing. Closing a socket
            // that still has unread received data makes Windows send RST
            // instead of a clean FIN (os error 10053/10054), which the client
            // then sees as a spurious error in the status line.
            drain_request(&mut stream);
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            // `write` results are intentionally ignored: the client may stop
            // reading early (e.g. when testing the size cap).
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(body);
            // Send a clean FIN before the stream is dropped.
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });

        format!("http://{addr}/payload.exe")
    }

    /// Reads and discards the client's HTTP request headers, so the socket has
    /// no unread data left when we close it (see [`serve_once`]).
    fn drain_request(stream: &mut std::net::TcpStream) {
        let mut buf = [0u8; 1024];
        let mut seen = 0usize;
        while seen < buf.len() {
            match Read::read(stream, &mut buf[seen..]) {
                Ok(0) => break,
                Ok(n) => {
                    seen += n;
                    // The request line and headers end with a blank line.
                    if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
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

    /// A reader that yields `data`, then either a connection reset or a clean
    /// EOF. Lets us exercise [`read_body`]'s reset tolerance without a socket.
    struct ResetAfterData {
        data: &'static [u8],
        pos: usize,
        reset_at_end: bool,
    }

    impl Read for ResetAfterData {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos < self.data.len() {
                let n = (self.data.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            } else if self.reset_at_end {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                ))
            } else {
                Ok(0)
            }
        }
    }

    #[test]
    fn reset_after_full_body_is_not_an_error() {
        let reader = ResetAfterData {
            data: b"complete body",
            pos: 0,
            reset_at_end: true,
        };
        let body = read_body(reader, Some(13), 1024).expect("a reset after the full body is OK");
        assert_eq!(body, b"complete body");
    }

    #[test]
    fn resets_before_body_is_complete_is_an_error() {
        let reader = ResetAfterData {
            data: b"trunc",
            pos: 0,
            reset_at_end: true,
        };
        let err = read_body(reader, Some(13), 1024).expect_err("a truncated body must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn reset_without_known_length_is_an_error() {
        let reader = ResetAfterData {
            data: b"data",
            pos: 0,
            reset_at_end: true,
        };
        read_body(reader, None, 1024).expect_err("a reset with no Content-Length must fail");
    }

    #[test]
    fn clean_eof_is_not_an_error() {
        let reader = ResetAfterData {
            data: b"clean",
            pos: 0,
            reset_at_end: false,
        };
        let body = read_body(reader, Some(5), 1024).expect("clean EOF must succeed");
        assert_eq!(body, b"clean");
    }
}
