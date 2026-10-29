/*
Package websocket implements the core of the WebSocket protocol from RFC 6455.

It covers the opening handshake key computation, frame encoding and decoding
with masking, fragmentation and reassembly, control frames, close codes, UTF-8
validation of text messages and a connection state machine. The package never
touches a socket: you feed it bytes that you read from any transport and send
the bytes it queues for you. That makes it usable over TCP, TLS, Unix sockets,
pipes or an in-memory test harness.

The package has three layers. Use the lowest one that fits:

- Handshake helpers: accept_key, generate_key, validate_client_request and
  friends compute and check the HTTP upgrade values.
- Frame codec: decode_header, encode_header, encode_frame and apply_mask read
  and write single frames without keeping any state.
- Connection: Conn tracks the role, reassembles fragmented messages,
  validates UTF-8, answers pings and runs the closing handshake.

Example:
	import "shared:websocket"

	main :: proc() {
		conn: websocket.Conn
		websocket.conn_init(&conn, .Server)
		defer websocket.conn_destroy(&conn)

		// Bytes read from the transport.
		_ = websocket.conn_receive(&conn, {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58})
		event, err := websocket.conn_next_event(&conn)
		if msg, ok := event.(websocket.Message); ok && err == nil {
			_ = msg.data // "Hello"
		}
	}
*/
package websocket

import "base:runtime"

/*
Opcode is the 4-bit frame type from RFC 6455 section 5.2.

Values 0x3 to 0x7 and 0xB to 0xF are reserved; decode_header rejects them.
*/
Opcode :: enum u8 {
	// A later fragment of a fragmented message.
	Continuation = 0x0,
	// The first or only frame of a text message.
	Text         = 0x1,
	// The first or only frame of a binary message.
	Binary       = 0x2,
	// Starts the closing handshake.
	Close        = 0x8,
	// Asks the peer to answer with a pong.
	Ping         = 0x9,
	// Answers a ping, or serves as a one-way heartbeat.
	Pong         = 0xA,
}

// opcode_is_control reports whether `op` is a control opcode (close, ping or pong).
opcode_is_control :: proc "contextless" (op: Opcode) -> bool {
	return u8(op) & 0x8 != 0
}

/*
Frame_Error lists the ways a frame header can be malformed, or why a frame
can't be written.
*/
Frame_Error :: enum {
	None,
	// The buffer ends before the header does. Read more bytes and try again.
	Incomplete,
	// RSV1, RSV2 or RSV3 is set, but no extension was negotiated.
	Reserved_Bits_Set,
	// The opcode is one of the reserved values.
	Reserved_Opcode,
	// A close, ping or pong frame has FIN cleared.
	Fragmented_Control_Frame,
	// A close, ping or pong frame carries more than 125 bytes.
	Control_Frame_Too_Long,
	// The 64-bit payload length has its most significant bit set.
	Payload_Length_Overflow,
	// The payload length used more bytes than needed.
	Non_Minimal_Length,
	// The destination buffer is too small for the frame.
	Buffer_Too_Small,
}

// Close_Error lists the ways the payload of a close frame can be malformed.
Close_Error :: enum {
	None,
	// The payload is one byte long, which can't hold a status code.
	Payload_Too_Short,
	// The status code isn't allowed on the wire, for example 1005 or 999.
	Invalid_Code,
	// The reason isn't valid UTF-8.
	Invalid_Utf8_Reason,
	// The reason is longer than 123 bytes, so the frame would exceed 125 bytes.
	Reason_Too_Long,
}

// Handshake_Error lists the ways an opening handshake can be rejected.
Handshake_Error :: enum {
	None,
	// The request method isn't GET.
	Invalid_Method,
	// The Upgrade header is missing or doesn't contain "websocket".
	Missing_Upgrade,
	// The Connection header is missing or doesn't contain "Upgrade".
	Missing_Connection,
	// The Sec-WebSocket-Key header is missing.
	Missing_Key,
	// The Sec-WebSocket-Key isn't the base64 encoding of 16 bytes.
	Invalid_Key,
	// The Sec-WebSocket-Version header isn't 13.
	Unsupported_Version,
	// The server answered with a status other than 101.
	Unexpected_Status,
	// The Sec-WebSocket-Accept header doesn't match the key that was sent.
	Accept_Mismatch,
}

// Conn_Error lists protocol violations and misuse detected by a Conn.
Conn_Error :: enum {
	None,
	// The connection already sent or received a close frame.
	Closed,
	// A server received a frame without a mask.
	Unmasked_Frame,
	// A client received a masked frame.
	Masked_Frame,
	// A continuation frame arrived with no message in progress.
	Unexpected_Continuation,
	// A text or binary frame arrived while a fragmented message was in progress.
	Expected_Continuation,
	// A text message isn't valid UTF-8.
	Invalid_Utf8,
	// A frame or message is larger than the configured limit.
	Message_Too_Big,
}

/*
Error is the compound error type returned by every fallible procedure in this
package. `nil` means success. Compare it with a specific variant, for example
`err == websocket.Frame_Error.Incomplete`, or use a type switch.
*/
Error :: union #shared_nil {
	Frame_Error,
	Close_Error,
	Handshake_Error,
	Conn_Error,
	runtime.Allocator_Error,
}

/*
Utf8_Validator checks UTF-8 incrementally, one chunk at a time.

It fails as soon as a byte makes the input invalid, even in the middle of a
fragmented message, which lets a connection reject bad text early. The zero
value is ready to use. A validator is safe to use from one thread at a time.
*/
Utf8_Validator :: struct {
	// Continuation bytes still expected for the current code point.
	need:   u8,
	// Inclusive range allowed for the next continuation byte.
	lo, hi: u8,
	// Set once invalid input is seen; stays set until utf8_reset.
	failed: bool,
}

// utf8_reset returns `v` to its initial state.
utf8_reset :: proc "contextless" (v: ^Utf8_Validator) {
	v^ = {}
}

/*
utf8_feed checks the next chunk of input.

Returns false as soon as the input so far can't be the prefix of valid UTF-8.
A true result means the input is valid so far; a code point may still be
incomplete, which utf8_finish detects.
*/
utf8_feed :: proc "contextless" (v: ^Utf8_Validator, data: []byte) -> bool {
	if v.failed {
		return false
	}
	need, lo, hi := v.need, v.lo, v.hi
	for b in data {
		if need == 0 {
			switch b {
			case 0x00 ..= 0x7F:
				continue
			case 0xC2 ..= 0xDF:
				need, lo, hi = 1, 0x80, 0xBF
			case 0xE0:
				need, lo, hi = 2, 0xA0, 0xBF // reject overlong forms
			case 0xED:
				need, lo, hi = 2, 0x80, 0x9F // reject UTF-16 surrogates
			case 0xE1 ..= 0xEC, 0xEE ..= 0xEF:
				need, lo, hi = 2, 0x80, 0xBF
			case 0xF0:
				need, lo, hi = 3, 0x90, 0xBF // reject overlong forms
			case 0xF1 ..= 0xF3:
				need, lo, hi = 3, 0x80, 0xBF
			case 0xF4:
				need, lo, hi = 3, 0x80, 0x8F // reject code points above U+10FFFF
			case:
				v.failed = true
				return false
			}
		} else {
			if b < lo || b > hi {
				v.failed = true
				return false
			}
			need -= 1
			lo, hi = 0x80, 0xBF
		}
	}
	v.need, v.lo, v.hi = need, lo, hi
	return true
}

// utf8_finish reports whether all input fed so far is complete, valid UTF-8.
utf8_finish :: proc "contextless" (v: ^Utf8_Validator) -> bool {
	return !v.failed && v.need == 0
}

// valid_utf8 reports whether `data` is complete, valid UTF-8 as RFC 3629 defines it.
valid_utf8 :: proc "contextless" (data: []byte) -> bool {
	v: Utf8_Validator
	return utf8_feed(&v, data) && utf8_finish(&v)
}
