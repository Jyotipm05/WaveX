# WaveX HTTP/3 & QPACK Architecture: RFC Compliance & Engineering Invariants

This reference guide documents the design, state management, and critical invariants governing the HTTP/3 binary framing layer (RFC 9114) and the QPACK header compression engine (RFC 9204) in WaveX.

---

## 1. Header AST Leanliness & Out-of-Line Separation (MSVC C1001 Mitigation)

### Architecture
To avoid internal compiler error crashes (`fatal error C1001: Internal compiler error in ParseTree`) on complex C++23 translation units:
- Non-template implementations, static tables, and complex parsers are placed in [`src/protos/http/http3codec.cpp`](../../../../src/protos/http/http3codec.cpp).
- [`include/wavex/protos/http/http3codec.hpp`](../../../../include/wavex/protos/http/http3codec.hpp) serves as a lightweight interface declaring:
  - `qpack::STATIC_TABLE` (`extern const std::array<static_entry, 99>`)
  - `qpack::dynamic_table` declarations
  - `qpack::encoder` and `qpack::decoder` declarations
  - `http3::parser`, `http3::encoder`, and `http3::decoder` declarations
- Templated methods (such as `session_handler::handle_unidirectional_stream<Stream>`) and one-line forwarding methods in `struct http3codec` remain in the header.

---

## 2. Resumable Request Parsing & Stream FIN Lifecycle (RFC 9114 §4.1)

### The Problem
If a parser returns `success` upon receiving the `HEADERS` frame while a subsequent `DATA` frame is still partially transmitted across the network, application route handlers process truncated bodies.

### The Invariants
1. **Resumable Parser State**:
   Requests maintain a `parser_state` tracking:
   ```c++
   struct parser_state {
       uint64_t content_length{0};
       uint64_t remaining_data_frame_bytes{0};
       std::size_t cursor{0};
       bool headers_received{false};
       bool has_content_length{false};
       bool in_data_frame{false};
   };
   ```
2. **Completion Criterion**:
   - When `Content-Length` is specified: parsing returns `incomplete` until `body_storage.size() == content_length`. If received bytes exceed `content_length`, `result::error` is returned immediately.
   - Without `Content-Length`: a request is only finalized upon stream FIN.
3. **Resumed Buffering**:
   Subsequent chunk reads resume consuming `remaining_data_frame_bytes` directly into `body_storage` without re-evaluating preceding frames.

---

## 3. Strict RFC 9114 Request & Header Validation

Per RFC 9114 §4.2 and §4.3, malformed requests must be rejected immediately with stream or connection errors:

1. **Lowercase Field Names**:
   Any uppercase character in header field names triggers a stream error.
2. **Pseudo-Header Order**:
   All pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`) must appear before regular headers.
3. **Duplicate Pseudo-Headers**:
   Duplicate pseudo-header occurrences (e.g. two `:method` fields) trigger `result::error`.
4. **Mandatory Pseudo-Headers**:
   `:method` and `:path` must always be present (except `:path` for `CONNECT` method).
5. **Connection-Specific Headers Prohibited**:
   Headers containing `connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, or non-trailers `te` trigger `result::error`.

---

## 4. QPACK Compression Engine (RFC 9204)

### Static Table
- RFC 9204 Appendix A defines a 99-entry static table (0-indexed, entries 0..98).
- Lookups use `find_static(name, value)` returning `std::pair<std::size_t, bool>`.

### Dynamic Table Lifetime & Scope
- **Connection Scope**: Dynamic tables are strictly scoped to the QUIC connection lifecycle via `connection_context.decode_table` (never instantiated per-stream or copied per-turn).
- **Capacity Limits**: Table capacity updates (`set_max_capacity`) are capped by the server's advertised setting (`SETTINGS_QPACK_MAX_TABLE_CAPACITY`).

### Indexing Schemes
1. **Relative Indexing (RFC 9204 §4.3.2)**:
   Dynamic table entry lookups inside stream field sections reference relative indices. The absolute index is computed as:
   $$\text{Absolute Index} = \text{Insert Count} - 1 - \text{Relative Index}$$
2. **Post-Base Indexing (RFC 9204 §4.5.3, §4.5.5)**:
   Entries inserted after the Base of a header block use post-base indexing:
   $$\text{Post-Base Index} = \text{Absolute Index} - \text{Base}$$
3. **Prefix Decoding (RFC 9204 §4.5.1.1)**:
   Decodes Required Insert Count (RIC) and Delta Base (Sign bit). When advertised table capacity is 0, any non-zero RIC is rejected as a decompression error.
4. **Huffman Bit on Literal Names**:
   The `H` bit (0x20 in literal name instructions) dictates whether literal field names are decoded via HPACK/QPACK Huffman tables or taken verbatim.

---

## 5. Unidirectional Stream Demultiplexing (RFC 9114 §6.2)

- Unidirectional streams opened by the client (`(sid & 0x03) == 0x02`) must **never** be treated as HTTP request streams or written to.
- They are read asynchronously by `session_handler::handle_unidirectional_stream`:
  - **Type `0x00` (Control Stream)**: Parses peer `SETTINGS` (updating `peer_qpack_max_table_capacity`, `max_field_section_size`, `peer_qpack_blocked_streams`) and handles `GOAWAY`.
  - **Type `0x02` (QPACK Encoder Stream)**: Processes `apply_encoder_instruction` on `ctx->decode_table`.
  - **Type `0x03` (QPACK Decoder Stream)**: Drains stream acknowledgements.
  - **Type `0x54` (WebTransport stream)**: Reads the session ID and hands the stream to `webtransport::dispatch_unidirectional_stream`.
- The control stream parser also records the peer's `ENABLE_CONNECT_PROTOCOL`, `H3_DATAGRAM` (0x33 and the draft 0xffd277), `WEBTRANSPORT_MAX_SESSIONS` and draft-02 `ENABLE_WEBTRANSPORT` in `connection_context`.

---

## 6. Extended CONNECT & Tunnels (RFC 9220, RFC 9297)

- `:protocol` is accepted only on `CONNECT`; an extended CONNECT must also carry `:scheme`, `:path` and `:authority`. The value is stored in `http3::request::protocol` and exposed as `HttpRequest::connect_protocol()`. `encoder::serialize_request` emits it (extension pseudo-headers precede regular fields).
- After the HEADERS of any CONNECT the parser stops: the rest of the stream is a tunnel, and `bytes_consumed` ends at the HEADERS frame so the takeover receives the following DATA frames as `unread` bytes.
- `http3::make_data_tunnel(AnyStream, leftover)` turns the stream into a byte stream: DATA payloads are concatenated, unknown frame types skipped, trailing HEADERS mean EOF, SETTINGS/GOAWAY/CANCEL_PUSH/MAX_PUSH_ID and reserved HTTP/2 types are a protocol error; each write becomes one DATA frame.
