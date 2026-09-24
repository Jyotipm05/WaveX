// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file wavex.hpp
 * @brief Main entry header for the WaveX framework.
 * 
 * This file declares core utility functions and macros, such as version information,
 * and includes essential protocol, routing, and server definitions.
 */

#pragma once

#include <wavex/Version.hpp>
#include <wavex/Base/Logger.hpp>
#include <wavex/Base/Chainable.hpp>
#include <wavex/Base/MimeTypes.hpp>
#include <wavex/Base/Event.hpp>
#include <wavex/protos/protos.hpp>
#include <wavex/protos/http/http.hpp>
#include <wavex/protos/ProtocolTraits.hpp>
#include <wavex/Engine/Router.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/Server/Server.hpp>
#include <wavex/Client/HttpClient.hpp>
#include <wavex/CLI/CLI.hpp>
#include <wavex/Async/SpawnBlocking.hpp>
#include <wavex/Utils/Utils.hpp>
