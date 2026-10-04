/**
 * @file QUIC.hpp
 * @brief Forwarding header for WaveX QUIC transport.
 *
 * For modular access, components are located in <wavex/Network/QUIC/*.hpp>.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <wavex/Network/QUIC/QUIC.hpp>
#endif
