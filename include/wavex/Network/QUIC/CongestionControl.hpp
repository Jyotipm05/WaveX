/**
 * @file CongestionControl.hpp
 * @brief RFC 9002 QUIC Loss Detection and Congestion Control.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <vector>

#include <wavex/Network/QUIC/QuicConstants.hpp>
#include <wavex/Network/QUIC/QuicFrames.hpp>

namespace wavex::network::quic {
    /**
     * @struct RttStats
     * @brief RFC 9002 §5 RTT Measurement and Estimator.
     */
    struct RttStats {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::chrono::microseconds latest_rtt{0};
        std::chrono::microseconds min_rtt{std::chrono::microseconds::max()};
        std::chrono::microseconds smoothed_rtt{std::chrono::microseconds(333000)}; // Initial RFC 9002 default: 333ms
        std::chrono::microseconds rttvar{std::chrono::microseconds(166500)}; // Initial RFC 9002 default: 333ms / 2
        bool first_rtt_sample{true};

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        constexpr RttStats() = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        void update_rtt(std::chrono::microseconds latest,
                        std::chrono::microseconds ack_delay = std::chrono::microseconds{0}) noexcept {
            latest_rtt = latest;
            if (min_rtt > latest) {
                min_rtt = latest;
            }
            if (first_rtt_sample) {
                min_rtt = latest;
                smoothed_rtt = latest;
                rttvar = latest / 2;
                first_rtt_sample = false;
                return;
            }
            // RFC 9002 §5.3: ack_delay adjustment
            std::chrono::microseconds adjusted_rtt = latest;
            if (latest >= min_rtt + ack_delay) {
                adjusted_rtt = latest - ack_delay;
            }
            // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
            const auto diff = (smoothed_rtt > adjusted_rtt)
                                  ? (smoothed_rtt - adjusted_rtt)
                                  : (adjusted_rtt - smoothed_rtt);
            rttvar = (rttvar * 3 + diff) / 4;
            // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
            smoothed_rtt = (smoothed_rtt * 7 + adjusted_rtt) / 8;
        }
    };

    /**
     * @struct SentPacket
     * @brief Tracks an in-flight packet for RFC 9002 loss detection.
     */
    struct SentPacket {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::chrono::steady_clock::time_point time_sent{};
        uint64_t packet_number{0};
        std::size_t bytes_sent{0};
        std::vector<Frame> retransmittable_frames{};
        PacketType packet_type{PacketType::Initial};
        bool ack_eliciting{true};
        bool in_flight{true};

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        SentPacket() = default;

        SentPacket(uint64_t pn, std::size_t bytes, PacketType pt,
                   std::chrono::steady_clock::time_point ts = std::chrono::steady_clock::now())
            : time_sent(ts), packet_number(pn), bytes_sent(bytes),
              packet_type(pt), ack_eliciting(true), in_flight(true) {
        }

        SentPacket(uint64_t pn, std::size_t bytes, PacketType pt,
                   std::vector<Frame> frames,
                   std::chrono::steady_clock::time_point ts = std::chrono::steady_clock::now())
            : time_sent(ts), packet_number(pn), bytes_sent(bytes),
              retransmittable_frames(std::move(frames)),
              packet_type(pt),
              ack_eliciting(!retransmittable_frames.empty()),
              in_flight(true) {
        }
    };

    /**
     * @class CongestionController
     * @brief RFC 9002 §7 Congestion Control and Loss Detection state machine.
     */
    class CongestionController {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        static constexpr uint64_t kMaxDatagramSize = 1200;
        static constexpr uint64_t kInitialWindow = 14720;
        // RFC 9002 §7.2: 10 * 1472 or min(10 * max_datagram_size, ...)
        static constexpr uint64_t kMinimumWindow = 2 * kMaxDatagramSize; // 2400
        static constexpr uint64_t kPacketThreshold = 3; // RFC 9002 §6.1.1

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::chrono::steady_clock::time_point recovery_start_time_{};
        uint64_t bytes_in_flight_{0};
        uint64_t congestion_window_{kInitialWindow};
        uint64_t ssthresh_{std::numeric_limits<uint64_t>::max()};
        RttStats rtt_stats_{};
        bool in_recovery_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        CongestionController() = default;

        ~CongestionController() = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] uint64_t bytes_in_flight() const noexcept { return bytes_in_flight_; }
        [[nodiscard]] uint64_t congestion_window() const noexcept { return congestion_window_; }
        [[nodiscard]] uint64_t ssthresh() const noexcept { return ssthresh_; }
        [[nodiscard]] const RttStats &rtt_stats() const noexcept { return rtt_stats_; }
        [[nodiscard]] bool in_recovery() const noexcept { return in_recovery_; }

        [[nodiscard]] bool can_send() const noexcept {
            return bytes_in_flight_ < congestion_window_;
        }

        void on_packet_sent(uint64_t bytes, bool in_flight = true) noexcept {
            if (in_flight) {
                bytes_in_flight_ += bytes;
            }
        }

        void on_packet_acked(uint64_t bytes) noexcept {
            if (bytes_in_flight_ >= bytes) {
                bytes_in_flight_ -= bytes;
            } else {
                bytes_in_flight_ = 0;
            }

            if (in_recovery_) return;

            // RFC 9002 §7.3.1: Slow Start
            if (congestion_window_ < ssthresh_) {
                congestion_window_ += bytes;
            } else {
                // RFC 9002 §7.3.2: Congestion Avoidance
                congestion_window_ += (kMaxDatagramSize * bytes) / congestion_window_;
            }
        }

        void on_congestion_event(std::chrono::steady_clock::time_point sent_time,
                                 std::chrono::steady_clock::time_point event_time = std::chrono::steady_clock::now())
            noexcept {
            if (sent_time <= recovery_start_time_) {
                return; // Already accounted for in current recovery period
            }
            recovery_start_time_ = event_time;
            in_recovery_ = true;

            // RFC 9002 §7.3.3: ssthresh = max(cwnd / 2, kMinimumWindow)
            ssthresh_ = (std::max)(congestion_window_ / 2, kMinimumWindow);
            congestion_window_ = ssthresh_;
        }

        void exit_recovery() noexcept {
            in_recovery_ = false;
        }

        void update_rtt(std::chrono::microseconds rtt_sample,
                        std::chrono::microseconds ack_delay = std::chrono::microseconds{0}) noexcept {
            rtt_stats_.update_rtt(rtt_sample, ack_delay);
        }
    };
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
