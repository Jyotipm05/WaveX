# WaveX QUIC Transport & Cryptographic Invariants

This rule governs RFC 9000, RFC 9001, and RFC 9002 compliance, wire framing, header protection, and connection lifetime across WaveX QUIC components.

---

## 1. Optional Dependency Guarding
- All QUIC and HTTP/3 headers and `.cpp` translation units must be guarded with `#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL`.
- In mock/fallback non-SSL builds, stub implementations must maintain clean zero-tag framing without invoking OpenSSL symbols.

---

## 2. Packet Number Offset & Header Protection (RFC 9001 §5.4)
- **Encryption (`protect_packet`)**:
  - `hdr.packet_number_len` must default to 4 if 0.
  - For long headers: `hdr.length = plaintext.size() + 16 + hdr.packet_number_len;`
  - Pack header to `header_bytes`, then compute `const std::size_t pn_offset = header_bytes.size() - hdr.packet_number_len;`
  - AES-128-GCM encrypt with `header_bytes` as Additional Authenticated Data (AAD).
  - Apply AES-128-ECB header protection sample from `ciphertext_out.data() + pn_offset + 4` with `EVP_CIPHER_CTX_set_padding(hp_ctx, 0)`.
  - Mask first byte (`0x0f` mask for long header, `0x1f` for short header) and packet number bytes at `ciphertext_out[pn_offset + i]`.
- **Decryption (`unprotect_packet`)**:
  - Unpack initial header to obtain `hdr.pn_offset`.
  - Sample 16 bytes from `packet_bytes.data() + hdr.pn_offset + 4` with `EVP_CIPHER_CTX_set_padding(hp_ctx, 0)`.
  - Unmask byte 0 and read `pn_len = (first_byte & 0x03) + 1`.
  - Unmask packet number bytes at `packet_bytes[hdr.pn_offset + i]`.
  - Reconstruct `unmasked_hdr` of length `hdr.pn_offset + pn_len` and supply it as AAD to `EVP_DecryptUpdate`.

---

## 3. ConnectionId Boundaries & Parsing
- Maximum Connection ID length is 20 bytes (`MAX_CONNECTION_ID_LEN`).
- `ConnectionId::from_hex(hex_str)` MUST validate that `hex_str.size()` is even, <= 40, and consists strictly of hex characters; otherwise it must return an empty `ConnectionId{}`.

---

## 4. Stream ID Demultiplexing & Background Draining (RFC 9000 §2.1)
- `(sid & 0x03) == 0x00`: Client-initiated bidirectional -> Dispatched to HTTP/3 request router.
- `(sid & 0x03) == 0x02`: Client-initiated unidirectional -> Drained in background (Peer Control / QPACK). Never treated as request streams and never written to.
- `(sid & 0x03) == 0x03`: Server-initiated unidirectional -> Stream 3 (Control/SETTINGS), Stream 7 (QPACK encoder), Stream 11 (QPACK decoder).

---

## 5. Stream Reassembly by Offset
- Incoming `StreamFrame` payloads must be reassembled by `frame.offset` via contiguous window buffering or ordered chunk collation.
- Detect and log `FINAL_SIZE_ERROR` if peer transmits data beyond a previously communicated FIN offset.

---

## 6. Timer Lifecycle, PTO Backoff & Connection Shutdown
- `QuicConnection::close()` MUST proactively cancel `loss_timer_` (`loss_timer_.cancel(ec)`) and set `state_ = ConnectionState::Closed`.
- `on_loss_detection_timeout()` must immediately return if `state_ == ConnectionState::Closed` before attempting frame retransmissions or rearming the timer.
- In automated unit tests, coroutines awaiting stream events or connection handshakes must explicitly stop their associated `asio::io_context` upon completion to prevent PTO backoff timers from stalling test executors.

