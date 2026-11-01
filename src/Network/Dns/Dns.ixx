// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Dns.ixx
 * @brief C++ module interface partition for the native DNS resolver.
 */

module;

#include <wavex/Network/Dns/DnsMessage.hpp>
#include <wavex/Network/Dns/Resolver.hpp>

export module wavex:dns;

export namespace wavex::dns {
    using dns::rr_type;
    using dns::rcode;
    using dns::svcb_data;
    using dns::message;
    using dns::record;
    using dns::errc;
    using dns::category;
    using dns::make_error_code;
    using dns::config;
    using dns::parse_resolv_conf;
    using dns::parse_hosts;
    using dns::system_config;
    using dns::resolve_options;
    using dns::resolver_options;
    using dns::addresses;
    using dns::resolver;
    using dns::build_query;
    using dns::parse_message;
}
