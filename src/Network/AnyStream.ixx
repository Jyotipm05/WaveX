// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file AnyStream.ixx
 * @brief C++ module interface partition for the type-erased transport stream in WaveX.
 */

module;

#include <wavex/Network/AnyStream.hpp>

export module wavex:network_any_stream;

export namespace wavex::network {
    using network::AnyStream;
}
