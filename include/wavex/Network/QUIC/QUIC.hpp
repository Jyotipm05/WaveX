/**
 * @file QUIC.hpp
 * @brief Main entry point for WaveX QUIC transport (RFC 9000, RFC 9001, RFC 9002).
 *
 * Include this single header to access all QUIC components.
 * Each component is in its own file for focused AI analysis.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

// ─── Core Types ────────────────────────────────────────────────────────────
#include <wavex/Network/QUIC/QuicConstants.hpp>
#include <wavex/Network/QUIC/VarInt.hpp>
#include <wavex/Network/QUIC/ConnectionId.hpp>

// ─── Protocol Structures ───────────────────────────────────────────────────
#include <wavex/Network/QUIC/QuicFrames.hpp>
#include <wavex/Network/QUIC/QuicPacket.hpp>
#include <wavex/Network/QUIC/QuicCrypto.hpp>

// ─── Transport Components ──────────────────────────────────────────────────
#include <wavex/Network/QUIC/CongestionControl.hpp>
#include <wavex/Network/QUIC/QuicStream.hpp>
#include <wavex/Network/QUIC/QuicConnection.hpp>

// ─── Server/Client & Sockets ───────────────────────────────────────────────
#include <wavex/Network/QUIC/QuicServer.hpp>
#include <wavex/Network/QUIC/QuicClient.hpp>
#include <wavex/Network/QUIC/QuicSocket.hpp>

#endif // WAVEX_HAS_SSL

