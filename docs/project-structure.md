# Project Structure

```text
include/wavex/
├── wavex.hpp                 main entry header (generated from wavex.hpp.in)
├── Version.hpp               generated version constant (wx_version)
├── Base/                     protocol-agnostic building blocks
│   ├── Request.hpp / Response.hpp   zero-vtable request/response bases (deducing this)
│   ├── Chainable.hpp         StaticChain, make_chain, KeepAlivePolicy
│   ├── MiddleWare.hpp        run_chain, keep_alive, sse_stay_active, body_limit
│   ├── FlatMap.hpp           contiguous key-value container
│   ├── Memory.hpp            RequestArena, ConnectionMemoryPool
│   ├── StringSink.hpp        string-sink concept for allocation-free serialization
│   ├── Event.hpp             Event, EventBus, ShutdownEvent
│   ├── Logger.hpp            levelled logger with source_location
│   ├── MimeTypes.hpp, Uri.hpp, Url.hpp
├── Async/SpawnBlocking.hpp   coroutine awaitable for blocking work
├── CLI/CLI.hpp               command-line parser
├── Client/HttpClient.hpp     HTTP/1.1 + HTTP/2 coroutine client
├── Engine/                   Router.hpp (radix tree + RE2), HttpRouter.hpp
├── Network/
│   ├── QUIC.hpp              umbrella header
│   └── QUIC/                 QuicServer/Client/Connection/Stream/Packet/Frames/Crypto,
│                             CongestionControl, ConnectionId, VarInt, QuicSocket, QuicConstants
├── Server/
│   ├── Server.hpp, ServerCore.hpp, ServerAliases.hpp, ComposedHttpServer.hpp
│   ├── ServerConfig.ipp, ServerConnection.ipp, ServerLifecycle.ipp, ServerQuic.ipp, ServerTls.ipp
│   ├── ThreadPool.hpp, WorkStealingQueue.hpp, BlockingPool.hpp
│   ├── ConnectionTracker.hpp, ServerState.hpp, TlsConfig.hpp
├── Utils/                    AsyncFs, BinaryFile, Compression, FsUtils, Multipart, StreamBuffer, TempFile, Utils.hpp
└── protos/
    ├── ProtocolTraits.hpp    protocol_traits<Codec> policy seam
    └── http/                 http1codec, http2codec, http3codec, HttpRequest, HttpResponse, Methods, http.hpp

src/            implementation files and C++ module interfaces (.ixx), mirrors include/
tests/          unit tests and the four interactive dev servers
cmake/          package config template (WaveXConfig.cmake.in)
ssl/            place for local dev certificates (git-ignored)
docs/           documentation and logo assets
.agents/        rules and skills used by AI coding agents (see CONTRIBUTING)
```
