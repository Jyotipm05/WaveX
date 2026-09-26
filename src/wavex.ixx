// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file wavex.ixx
 * @brief Primary C++ module interface file for the WaveX framework.
 * 
 * Exports the main WaveX namespace symbols, functions, and submodule partitions.
 */

module;

#include <wavex/wavex.hpp>

export module wavex;

#if !defined(__GNUC__) || defined(__clang__)
// Active in MSVC / Clang: Aggregate submodule partitions
export import :chainable;
export import :logger;
export import :protos;
export import :protos_http;
export import :middleware;
export import :router;
export import :http_router;
export import :server;
export import :client;
export import :cli;
export import :utils;

export namespace wavex {
    using wavex::_version;
    std::string_view wx_version = ::wx_version;
}
#else
// Deactivated in GCC to prevent cross-partition internal-linkage symbol collisions (ISO P2808R0)
export namespace wavex {
    using wavex::protocol;
    using wavex::_version;
    using wavex::spawn_blocking;
    std::string_view wx_version = ::wx_version;
}

export namespace wavex::base {
    using base::Chainable;
    using base::StaticChain;
    using base::make_chain;
    using base::LogLevel;
    using base::Logger;
    using base::set_log_level;
    using base::log;
    using base::Next;
    using base::Middleware;
}

export namespace wavex::protos {
    using protos::protocol_traits;
}

export namespace wavex::protos::http {
    using http::method;
    using http::header;
    using http::message_base;
    using http::request;
    using http::response;
    using http::to_string;
    using http::from_string;
    using http::status_text_for;
    using http::parser;
    using http::encoder;
    using http::decoder;
    using http::http1codec;
    using http::http2codec;
    using http::HttpRequest;
    using http::Http1Request;
    using http::http1request;
    using http::Http2Request;
    using http::http2request;
    using http::Http3Request;
    using http::http3request;
    using http::HttpResponse;
    using http::Http1Response;
    using http::http1response;
    using http::Http2Response;
    using http::http2response;
    using http::Http3Response;
    using http::http3response;
}

export namespace wavex::engine {
    using engine::Router;
    using engine::HttpRouter;
    using engine::http_router;
    using engine::Http3Router;
    using engine::http3router;
}

export namespace wavex::server {
    using server::TlsConfig;
    using server::Task;
    using server::LocalQueue;
    using server::InjectorQueue;
    using server::ThreadPoolConfig;
    using server::WorkerNode;
    using server::ThreadPool;
    using server::BlockingTask;
    using server::BlockingThreadPool;
    using server::ConnectionTracker;
    using server::Server;
    using server::Http1Server;
    using server::http1server;
    using server::Http2Server;
    using server::http2server;
    using server::Http3Server;
    using server::http3server;
    using server::HttpServer;
    using server::httpserver;
}

export namespace wavex::network::quic {
    using quic::QuicVersion;
    using quic::PacketType;
    using quic::TransportError;
    using quic::FrameType;
    using quic::VarInt;
    using quic::ConnectionId;
    using quic::QuicStream;
    using quic::QuicConnection;
    using quic::QuicServer;
    using quic::QuicClient;
}


export namespace wavex::client {
    using client::HttpVersion;
    using client::ClientOptions;
    using client::QueryParams;
    using client::ClientRequest;
    using client::ClientResponse;
    using client::HttpClient;
    using protos::http::method;
    using enum wavex::protos::http::method;
}

export namespace wavex::cli {
    using cli::CLI;
    using cli::App;
}

export namespace wavex::utils {
    using utils::FileMode;
    using utils::BinaryFile;
    using utils::TempFileGuard;
    using utils::CompressionFormat;
    using utils::Compressor;
    using utils::UploadedFile;
    using utils::FormField;
    using utils::MultipartLimits;
    using utils::MultipartFormData;
}

export namespace wavex::fs {
    using fs::read_file;
    using fs::read_bytes;
    using fs::write_file;
    using fs::append_file;
    using fs::remove;
    using fs::copy_file;
}
#endif
