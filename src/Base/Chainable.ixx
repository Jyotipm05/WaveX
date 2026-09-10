// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Chainable.ixx
 * @brief C++ module interface for wavex::Chainable static dispatch.
 */

module;

#include <wavex/Base/Chainable.hpp>

export module wavex:chainable;

export namespace wavex {
    using wavex::Chainable;
    using wavex::ChainableHandler;
    using wavex::StaticChain;
    using wavex::make_chain;
    using wavex::ConditionalChainable;
    using wavex::KeepAlivePolicy;
}

