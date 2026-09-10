// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file protos.ixx
 * @brief C++ module interface for protocol definitions.
 */

module;
#include <wavex/protos/protos.hpp>
#include <wavex/protos/ProtocolTraits.hpp>
export module wavex:protos;

export namespace wavex {
    using wavex::protocol;
}

export namespace wavex::protos {
    using wavex::protos::protocol_traits;
}
