// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file WebTransport.ixx
 * @brief C++ module interface partition for WebTransport over HTTP/3 in WaveX.
 */

module;

#include <wavex/protos/webtransport/WebTransport.hpp>

export module wavex:protos_webtransport;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
export namespace wavex::protos::webtransport {
    using webtransport::kBidiStreamSignal;
    using webtransport::kUniStreamType;
    using webtransport::kCapsuleCloseSession;
    using webtransport::kCapsuleDrainSession;
    using webtransport::kMaxCloseReasonBytes;
    using webtransport::kProtocolToken;
    using webtransport::error;
    using webtransport::error_category;
    using webtransport::make_error_code;
    using webtransport::options;
    using webtransport::stream;
    using webtransport::session;
    using webtransport::session_registry;
    using webtransport::registry_for;
    using webtransport::http3_context_for;
    using webtransport::dispatch_bidirectional_stream;
    using webtransport::dispatch_unidirectional_stream;
    using webtransport::handler_fn;
    using webtransport::accept;

    namespace capsule {
        using capsule::parse_result;
        using capsule::parse;
        using capsule::encode;
        using capsule::encode_close_session;
        using capsule::decode_close_session;
    }
}
#endif
