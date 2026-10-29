# Changelog

This file records all notable changes to this project.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-29

### Added

- Handshake helpers: `accept_key`, `generate_key`, `new_key`, `is_valid_key`, `header_has_token`, `validate_client_request`, `validate_server_response`, `select_subprotocol`, `server_response` and `client_request`.
- Frame codec: `decode_header`, `encode_header`, `encode_frame`, `encode_frame_into`, `header_size` and `apply_mask`, with checks for reserved bits, reserved opcodes, control frame rules and minimal length encoding.
- Close codes: `Close_Code`, `close_code_is_valid`, `encode_close_payload` and `decode_close_payload`.
- UTF-8 checks: `valid_utf8` and the incremental `Utf8_Validator`, which fails fast inside fragmented messages.
- `Conn`, a transport-agnostic connection state machine with fragment reassembly, automatic pongs, the closing handshake, message size limits and outgoing fragmentation.
- Examples `basic` (in-memory client and server) and `echo_server` (TCP echo server on `core:net`).

[Unreleased]: https://github.com/alexisbcz/odin-websocket/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alexisbcz/odin-websocket/releases/tag/v0.1.0
