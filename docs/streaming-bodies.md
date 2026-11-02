# Streaming response bodies

`HttpClient::send()` returns the whole body in memory. For large downloads, long-lived responses (event streams,
log tails) or anything you want to process as it arrives, use `send_streaming()`:

```cpp
std::ofstream out("big.bin", std::ios::binary);
auto res = co_await wavex::client::HttpClient::send_streaming(
    wavex::client::ClientRequest(wavex::client::method::GET, "https://example.com/big.bin"),
    wavex::client::ClientOptions{},
    [&](std::string_view chunk) -> wavex::task<bool> {
        out.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        co_return true;                       // false aborts the download
    });

if (res.status_code() != 200 || res.body_error()) { /* failed or incomplete */ }
```

* The sink gets each piece in order with the framing already removed (HTTP/1.1 chunking, HTTP/2 DATA frames,
  HTTP/3 DATA frames). The pieces are views into the read buffer: copy what you need to keep.
* The next read does not start until the sink's task completes. A slow sink therefore slows the transfer (the
  kernel's TCP window or QUIC flow control fills up); memory use stays at one read buffer (16 KiB).
* The returned response has status and headers and an empty `body()`. `body_error()` is empty when the whole body
  arrived, `std::errc::operation_canceled` when the sink returned `false`, and `connection_reset` /
  `protocol_error` when the connection ended early or the framing was invalid. A failure before the status line
  still yields a 502 like `send()`.
* Works over HTTP/1.1, HTTP/2 and HTTP/3 (`ClientOptions::version`, `h3_discovery`), and through `Http3Client::send_streaming()`.

## Where the framing lives

The incremental parsers are part of the codecs, so the client only moves bytes:

| Codec        | Class                           | Notes                                                                                                   |
|--------------|---------------------------------|---------------------------------------------------------------------------------------------------------|
| `http1codec` | `response_stream_parser`        | Content-Length, chunked (extensions, trailers), until-close, HEAD, interim 1xx                          |
| `http3codec` | `http3::response_stream_parser` | QPACK-decoded head, DATA delivered without waiting for whole frames, trailers, extension frames skipped |

Both are pure state machines (no I/O): `next(input)` consumes from the front of `input` and returns
`head` / `body` / `done` (HTTP/1.x) or `need_more` / `error`; `finish()` tells you at end of stream whether the
message was complete. They are tested at every split size, with truncated and hostile input.

## Limits

* HTTP/2 over TCP opens its receive window fully, so backpressure is TCP-level, not per-stream.
* There is no pull-style reader yet (`co_await read_chunk()`); the sink is the single entry point.
