# WaveX QUIC Transport & Reliability Architecture: Learnings & Invariants

This document captures the engineering challenges, bugs encountered, and definitive design invariants established while implementing and stabilizing QUIC (RFC 9000, RFC 9001, RFC 9002) in WaveX.

---

## 1. Handshake State Machine Gating & Fallback Traps

### The Bug
During MTU splitting and address validation tests, a client sent a `Handshake` packet to validate its IP address under RFC 9000 §8.1.
Inside `QuicConnection::handle_datagram`:
```cpp
// INCORRECT (OLD):
if (is_server_ && state_ == ConnectionState::Initial) {
    if (!tls_ || !tls_->initialized) {
        send_initial_handshake_response();
        state_ = ConnectionState::Connected;
    }
}
```
Because `state_ == ConnectionState::Initial` was true, the server erroneously called `send_initial_handshake_response()`. This built and enqueued:
1. An `Initial` ACK packet for Packet Number Space 0.
2. A `1-RTT` packet containing `HANDSHAKE_DONE`.

When the test subsequently queued 3,500 bytes of stream data (expecting 4 packets of 1,150 + 1,150 + 1,150 + 50 bytes), draining the outbound queue yielded **6 packets instead of 4**, causing an assertion failure:
```
Assertion failed: pkts.size() == 4, line 1482
```

### The Root Cause
A server Initial handshake response represents the server's reply to a client's **Initial** packet. Non-Initial packets (such as client `Handshake` packets sent to validate addresses before handshake keys are negotiated) must **never** trigger Initial packet responses.

### The Fix & Invariant
Server Initial responses and mock/non-TLS completion must strictly check `has_received_initial_`:
```cpp
// CORRECT:
if (is_server_ && state_ == ConnectionState::Initial && has_received_initial_) {
    if (!tls_ || !tls_->initialized) {
        send_initial_handshake_response();
        state_ = ConnectionState::Connected;
    }
}
```
`has_received_initial_` is only set after an `Initial` packet has successfully been unpacked and decrypted.

---

## 2. Peer Address Validation vs. Handshake Packet Buffering (RFC 9000 §8.1)

### The Principle
Under RFC 9000 §8.1, until the client's network address is validated, the server must not send more than 3× the cumulative bytes received (`cumulative_bytes_sent_ <= 3 * cumulative_bytes_received_`).
Receipt of **any** Handshake packet from the client confirms the client's address (`peer_address_validated_ = true`), unblocking normal transmission limits.

### Implementation Invariant
1. As soon as a client packet with long header `type == PacketType::Handshake` is observed, immediately set:
   ```cpp
   peer_address_validated_ = true;
   ```
2. If `handshake_keys_peer_` are not yet available (e.g. TLS engine has not completed Initial crypto exchange), buffer the raw packet in `buffered_handshake_packets_` (capped to 16) and `continue;`.
3. Do **not** fail the connection or trigger fallbacks until keys are installed and buffered packets are drained.

---

## 3. RFC 9002 Loss Detection & PTO Exponential Backoff

### The Architecture
QUIC does not use TCP cumulative ACKs; packets are acknowledged by explicit packet number ranges in `AckFrame`.

### Sent Packet Tracking
1. Every outgoing ack-eliciting packet is recorded in `sent_packets_[space_idx]` (Initial, Handshake, Application spaces):
   ```cpp
   struct SentPacket {
       uint64_t packet_number;
       std::size_t bytes_sent;
       std::chrono::steady_clock::time_point time_sent;
       std::vector<Frame> frames;
       bool ack_eliciting{true};
       bool in_flight{true};
   };
   ```
2. When an ACK is received:
   - Calculate RTT samples using `time_sent` of the largest newly acknowledged packet.
   - Detect packet loss using:
     - **Packet Threshold**: If `largest_acked - pn >= 3`, declare the packet lost.
     - **Time Threshold**: If `now - time_sent >= (9/8) * max(smoothed_rtt, latest_rtt)`, declare lost.
3. For lost packets:
   - Identify ack-eliciting frames (`StreamFrame`, `CryptoFrame`, `PingFrame`).
   - Re-queue frames into stream send queues or crypto retransmission buffers.
   - Do **not** retransmit the original packet number; emit a new packet with an incremented packet number.

### PTO (Probe Timeout) Timer Lifecycle
- An active `asio::steady_timer loss_detection_timer_` arms whenever packets are in flight.
- If the timer fires before an ACK arrives:
  - Increment `pto_count_`.
  - Double the PTO duration (exponential backoff).
  - Transmit 1 or 2 probe frames (e.g. `PingFrame` or unacknowledged stream data) to elicit an ACK from the peer.
- **Critical Cleanup**: When `close()` is invoked, immediately call `loss_detection_timer_->cancel(ec)` and check `if (state_ == ConnectionState::Closed) return;` at the entry of the timer callback.

---

## 4. Out-of-Order Stream Reassembly & Offset Sorting

### The Problem
UDP packets can arrive duplicated, reordered, or fragmented. Appending incoming data sequentially causes silent body corruption.

### The Invariant
Every `QuicStream` maintains an ordered offset reassembler:
1. Inbound payload slices are stored in a sorted structure (`std::map<uint64_t, StreamChunk> pending_inbound_`).
2. Only contiguous bytes starting from `inbound_read_offset_` are moved into the readable buffer.
3. Overlapping and duplicate byte ranges are truncated or dropped.
4. **Final Size Consistency**:
   - When a frame with `fin == true` arrives, record `final_size_ = offset + data.size()`.
   - If a subsequent frame exceeds `final_size_`, or if another FIN arrives with a different final size, immediately trigger `FINAL_SIZE_ERROR` and reset the stream.

---

## 5. Flow Control & MTU Packetization (RFC 9000 §4 & §14)

### MTU Framing
- UDP packets exceeding network path MTU (~1280 bytes IPv6 / 1500 bytes Ethernet) are dropped.
- Stream data is chunked into frames with `kMaxStreamFramePayload = 1150` bytes.
- Stream send queues maintain per-stream pending byte buffers (`stream_send_queues_[sid]`).

### Credit Accounting
- **Connection-Level**: `conn_credit = max_data_ - data_sent_`.
- **Stream-Level**: `stream_credit = max_stream_data_ - stream_sent`.
- The maximum frame payload size sent in any turn is bounded by `min({chunk_len, conn_credit, stream_credit, kMaxStreamFramePayload})`.
