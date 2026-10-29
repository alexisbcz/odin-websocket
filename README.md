# `websocket`

[![CI](https://github.com/alexisbcz/odin-websocket/actions/workflows/ci.yml/badge.svg)](https://github.com/alexisbcz/odin-websocket/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Odin](https://img.shields.io/badge/Odin-dev--2026--09-1e5a99.svg)](https://odin-lang.org)

A transport-agnostic [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) WebSocket core for Odin: handshake keys, frame encoding with masking, fragmentation, control frames, close codes, UTF-8 checks and a connection state machine that works over any byte stream.

The package never opens a socket. You read bytes from TCP, TLS, a pipe or a test buffer, hand them to a `Conn`, and write back the bytes it queues. That keeps the protocol logic testable and lets you use it with any event loop.

## Install

The repository root is the package, so you can vendor it in two ways.

As a Git submodule inside your project:

```sh
git submodule add https://github.com/alexisbcz/odin-websocket libs/websocket
```

```odin
import "libs/websocket"
```

As a copy in a shared collection that all your projects use:

```sh
git clone https://github.com/alexisbcz/odin-websocket ~/odin-shared/websocket
odin build . -collection:shared=$HOME/odin-shared
```

```odin
import "shared:websocket"
```

## Quick start

A server answers the upgrade request, then feeds socket bytes to a `Conn` and echoes every message:

```odin
package main

import "core:fmt"
import ws "shared:websocket"

main :: proc() {
	// Handshake: check the request headers, then send the 101 response.
	req := ws.Client_Request {
		method     = "GET",
		upgrade    = "websocket",
		connection = "Upgrade",
		key        = "dGhlIHNhbXBsZSBub25jZQ==",
		version    = "13",
	}
	if err := ws.validate_client_request(req); err != .None {
		fmt.eprintln("bad handshake:", err)
		return
	}
	response, _ := ws.server_response(req.key)
	defer delete(response)
	fmt.print(response) // write this to the socket

	conn: ws.Conn
	ws.conn_init(&conn, .Server)
	defer ws.conn_destroy(&conn)

	// Bytes read from the socket: the masked "Hello" frame from RFC 6455.
	_ = ws.conn_receive(&conn, {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58})
	for {
		event, err := ws.conn_next_event(&conn)
		if err != nil {
			fmt.eprintln("protocol error:", err) // a close frame is already queued
			break
		}
		if event == nil {
			break // need more bytes
		}
		#partial switch e in event {
		case ws.Message:
			fmt.println("got:", ws.message_text(e))
			_ = ws.conn_send_message(&conn, e.kind, e.data)
		case ws.Close:
			fmt.println("peer closed:", e.code)
		}
	}

	out := ws.conn_outgoing(&conn) // write these bytes to the socket
	fmt.println("queued", len(out), "bytes")
	ws.conn_consume_outgoing(&conn, len(out))
}
```

## API overview

| Declaration | Purpose | Allocates | Free with |
| --- | --- | --- | --- |
| `accept_key(key)` | Compute `Sec-WebSocket-Accept` from a client key | No | Not needed |
| `new_key()`, `generate_key(nonce)` | Make a `Sec-WebSocket-Key` | No | Not needed |
| `validate_client_request(req)` | Check a server-side upgrade request | No | Not needed |
| `validate_server_response(...)` | Check a client-side upgrade response | No | Not needed |
| `server_response(key, protocol, allocator)` | Build the `101` response head | Yes | `delete` |
| `client_request(host, path, key, protocols, allocator)` | Build the upgrade request head | Yes | `delete` |
| `select_subprotocol(offered, supported)` | Pick a subprotocol in server order | No | Not needed |
| `decode_header(data)`, `encode_header(buf, h)` | Read and write a frame header | No | Not needed |
| `encode_frame(h, payload, allocator)` | Encode a complete frame | Yes | `delete` |
| `encode_frame_into(buf, h, payload)` | Encode a frame into your buffer | No | Not needed |
| `apply_mask(data, key, offset)` | Mask or unmask a payload in place | No | Not needed |
| `encode_close_payload`, `decode_close_payload` | Close frame status code and reason | No | Not needed |
| `valid_utf8(data)`, `Utf8_Validator` | One-shot and incremental UTF-8 checks | No | Not needed |
| `Conn` | Connection state machine | Yes | `conn_destroy` |
| `conn_receive(c, data)` | Buffer bytes read from the transport | Yes | `conn_destroy` |
| `conn_next_event(c)` | Parse the next `Message`, `Ping`, `Pong` or `Close` | Yes | `conn_destroy` |
| `conn_send_text`, `conn_send_binary`, `conn_send_message` | Queue a data message | Yes | `conn_destroy` |
| `conn_send_ping`, `conn_send_pong`, `conn_close` | Queue a control frame | Yes | `conn_destroy` |
| `conn_outgoing(c)`, `conn_consume_outgoing(c, n)` | Drain bytes for the transport | No | Not needed |
| `Error` | Union of `Frame_Error`, `Close_Error`, `Handshake_Error`, `Conn_Error` and `runtime.Allocator_Error` | No | Not needed |

### What a Conn handles for you

- Masking: a client masks every frame it sends; a server rejects unmasked frames and a client rejects masked ones.
- Fragmentation: the `Conn` reassembles continuation frames and delivers control frames that arrive between fragments right away. Set `Config.fragment_size` to fragment outgoing messages.
- UTF-8: the `Conn` validates text messages as they arrive, so bad input fails the connection with close code 1007 before the last fragment.
- Pings: each ping gets a pong with the same payload, unless you set `Config.manual_pong`.
- Closing: the `Conn` echoes a peer's close frame, `conn_close` moves to `.Closing` until the peer answers, and `conn_should_close` says when to close the transport.
- Limits: messages larger than `Config.max_message_size` (16 MiB by default) fail with close code 1009, and the check runs on the header, before any payload bytes reach the buffer.
- Failures: protocol errors queue a close frame with code 1002, 1007 or 1009 and return the specific error value.

## Examples

Each directory under `examples/` is a runnable program:

```sh
odin run examples/basic        # client and server Conn wired together in memory
odin run examples/echo_server  # echo server on ws://127.0.0.1:9001 using core:net
```

## Design notes

- Event data borrows memory owned by the `Conn` and stays valid until the next `conn_receive` or `conn_next_event` call. Copy it to keep it. The `Conn` delivers single-frame messages without a copy.
- Every allocating procedure takes `allocator := context.allocator` and says who owns the result. A `Conn` stores its allocator and uses it for all its buffers.
- Fallible procedures return `Error`, with a specific enum member for each failure. The library never panics on bad input.
- Client masking keys come from `core:crypto` system entropy. Set `Config.mask_key_proc` to supply your own, for example in tests.
- Extensions such as `permessage-deflate` aren't implemented. `decode_header` takes `allow_rsv = true` for code that adds one on top.
- The package keeps no global mutable state. A `Conn` is safe to use from one thread at a time.

## Testing

```sh
odin check . -vet -strict-style -disallow-do -no-entry-point
odin test tests -vet -strict-style -disallow-do
vale sync && vale *.md
```

The tests use the examples from RFC 6455 and cases modeled on the Autobahn test suite: reserved bits and opcodes, fragmented and too-long control frames, interleaved pings, invalid UTF-8 that must fail fast, close codes and frames that arrive one byte at a time.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Commits follow Conventional Commits, and every change that users can see gets a line in [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
