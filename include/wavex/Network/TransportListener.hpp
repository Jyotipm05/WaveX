/**
 * @file TransportListener.hpp
 * @brief Transport seam: an extra listener (e.g. QUIC/UDP) a server runs next to its TCP acceptor.
 *
 * The generic Server<Codec, Router> only ever sees this interface. Concrete listeners live with their
 * transport (see Network/QUIC/QuicListener.hpp) and are produced by protocol_traits<Codec>.
 */

#pragma once

namespace wavex::network {
    class TransportListener {
    public:
        virtual ~TransportListener() = default;

        /// Bind and begin accepting. May throw if the configuration is invalid (e.g. TLS required but absent).
        virtual void start() = 0;

        /// Stop accepting and release the transport. Idempotent; callable from any thread.
        virtual void stop() noexcept = 0;
    };
} // namespace wavex::network
