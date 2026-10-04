// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Server.hpp
 * @brief Main entry point for WaveX server components.
 *
 * This header aggregates all server components. Include this single file
 * to get the complete Server template, ConnectionTracker, ComposedHttpServer,
 * and type aliases.
 *
 * @note Internal implementation details are in .ipp files included at the
 *       bottom of this header. Do not include those directly.
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

// ─── Component Includes ────────────────────────────────────────────────────
#include <wavex/Server/ServerState.hpp>
#include <wavex/Server/ConnectionTracker.hpp>
#include <wavex/Server/ServerCore.hpp>

// ─── Template Implementations ──────────────────────────────────────────────
#include <wavex/Server/ServerLifecycle.ipp>
#include <wavex/Server/ServerConnection.ipp>
#include <wavex/Server/ServerConfig.ipp>
#include <wavex/Server/ServerTls.ipp>
#include <wavex/Server/ServerQuic.ipp>

// ─── High-Level Components & Aliases ───────────────────────────────────────
#include <wavex/Server/ServerAliases.hpp>
#include <wavex/Server/ComposedHttpServer.hpp>
