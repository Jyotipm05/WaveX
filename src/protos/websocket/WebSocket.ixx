// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file WebSocket.ixx
 * @brief C++ module interface partition for WebSocket (RFC 6455 / RFC 9220) in WaveX.
 */

module;

#include <wavex/protos/websocket/WebSocket.hpp>

export module wavex:protos_websocket;

export namespace wavex::protos::websocket {
    using websocket::kHandshakeGuid;
    using websocket::kProtocolVersion;
    using websocket::opcode;
    using websocket::is_control;
    using websocket::role;
    using websocket::error;
    using websocket::error_category;
    using websocket::make_error_code;
    using websocket::frame_header;
    using websocket::parse_result;
    using websocket::codec;
    using websocket::compute_accept_key;
    using websocket::is_valid_client_key;
    using websocket::generate_client_key;
    using websocket::header_contains_token;
    using websocket::is_valid_utf8;
    using websocket::options;
    using websocket::message;
    using websocket::connection;
    using websocket::handler_fn;
    using websocket::accept;

    namespace close_code {
        using close_code::normal;
        using close_code::going_away;
        using close_code::protocol_error;
        using close_code::unsupported_data;
        using close_code::no_status;
        using close_code::abnormal;
        using close_code::invalid_payload;
        using close_code::policy_violation;
        using close_code::message_too_big;
        using close_code::mandatory_extension;
        using close_code::internal_error;
    }
}
