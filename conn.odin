package websocket

import "base:runtime"
import "core:crypto"

// DEFAULT_MAX_MESSAGE_SIZE is the message size limit a Conn uses when Config leaves it at zero.
DEFAULT_MAX_MESSAGE_SIZE :: 16 * 1024 * 1024

// Role says which side of the connection a Conn plays. It decides masking.
Role :: enum {
	// Masks every frame it sends and rejects masked frames it receives.
	Client,
	// Rejects unmasked frames and never masks the frames it sends.
	Server,
}

// State is the stage of the closing handshake that a Conn has reached.
State :: enum {
	// Both directions are open.
	Open,
	// This side sent a close frame and waits for the peer's close frame.
	Closing,
	// Both close frames have been exchanged, or the connection failed.
	// Flush conn_outgoing, then close the transport.
	Closed,
}

/*
Mask_Key_Proc returns a fresh masking key for one outgoing client frame.
RFC 6455 requires keys that the network can't predict.
*/
Mask_Key_Proc :: #type proc(user_data: rawptr) -> [4]byte

/*
Config tunes a Conn. The zero value gives sensible defaults.
*/
Config :: struct {
	// Largest message, after reassembly, the Conn accepts. Larger ones fail
	// the connection with close code 1009. Zero means DEFAULT_MAX_MESSAGE_SIZE.
	max_message_size: int,
	// When positive, conn_send_text and conn_send_binary split messages into
	// fragments of at most this many payload bytes.
	fragment_size:    int,
	// When set, the Conn doesn't answer pings; call conn_send_pong yourself.
	manual_pong:      bool,
	// Source of client masking keys. When nil, the Conn uses system entropy.
	mask_key_proc:    Mask_Key_Proc,
	// Passed to mask_key_proc unchanged.
	mask_key_data:    rawptr,
}

// Message_Kind tells text messages from binary ones.
Message_Kind :: enum {
	Text,
	Binary,
}

/*
Message is a complete data message, reassembled from its fragments.
`data` borrows memory owned by the Conn. It stays valid until the next call
to conn_receive or conn_next_event; copy it to keep it longer. Text messages
are already checked to be valid UTF-8.
*/
Message :: struct {
	kind: Message_Kind,
	data: []byte,
}

// message_text returns the data of a text message as a string. It borrows the same memory.
message_text :: proc "contextless" (m: Message) -> string {
	return string(m.data)
}

/*
Ping is a received ping. Unless Config.manual_pong is set, the Conn has
already queued the matching pong. `payload` borrows Conn memory like Message.
*/
Ping :: struct {
	payload: []byte,
}

// Pong is a received pong. `payload` borrows Conn memory like Message.
Pong :: struct {
	payload: []byte,
}

/*
Close is a received close frame. When the peer started the closing
handshake, the Conn has already queued the echoing close frame. `reason`
borrows Conn memory like Message. `code` is `.No_Status` when the frame had
no payload.
*/
Close :: struct {
	code:   Close_Code,
	reason: string,
}

// Event is what conn_next_event returns. `nil` means more input is needed.
Event :: union {
	Message,
	Ping,
	Pong,
	Close,
}

/*
Conn is a transport-agnostic WebSocket connection state machine.

Feed it bytes from the transport with conn_receive, pull events with
conn_next_event, and write the bytes from conn_outgoing back to the
transport. Create one with conn_init and release it with conn_destroy.

A Conn is safe to use from one thread at a time.
*/
Conn :: struct {
	role:           Role,
	state:          State,
	config:         Config,
	allocator:      runtime.Allocator,

	inbound:        [dynamic]byte,
	in_pos:         int,
	outbound:       [dynamic]byte,
	out_pos:        int,

	message:        [dynamic]byte,
	message_kind:   Message_Kind,
	in_message:     bool,
	message_ready:  bool,
	utf8:           Utf8_Validator,

	close_sent:     bool,
	close_received: bool,
	failed:         bool,
	// The close code this side sent, or `.No_Status` before that.
	sent_code:      Close_Code,
	mask_state:     u64,
}

/*
conn_init prepares `c` for use in the Open state.

Inputs:
- c: the connection to initialize; any previous content is overwritten.
- role: `.Client` or `.Server`.
- config: limits and options; the zero value gives the defaults.
- allocator: used for every buffer the Conn owns. Call conn_destroy when done.
*/
conn_init :: proc(c: ^Conn, role: Role, config := Config{}, allocator := context.allocator) {
	c^ = {}
	c.role = role
	c.config = config
	if c.config.max_message_size <= 0 {
		c.config.max_message_size = DEFAULT_MAX_MESSAGE_SIZE
	}
	c.allocator = allocator
	c.inbound = make([dynamic]byte, allocator)
	c.outbound = make([dynamic]byte, allocator)
	c.message = make([dynamic]byte, allocator)
	c.sent_code = .No_Status
	c.mask_state = u64(uintptr(c)) ~ 0x9E3779B97F4A7C15
}

// conn_destroy frees every buffer owned by `c` and zeroes it.
conn_destroy :: proc(c: ^Conn) {
	delete(c.inbound)
	delete(c.outbound)
	delete(c.message)
	c^ = {}
}

// conn_state returns the closing handshake stage of `c`.
conn_state :: proc "contextless" (c: ^Conn) -> State {
	return c.state
}

/*
conn_should_close reports whether the transport can be closed: the closing
handshake finished, or the connection failed, and every queued byte has been
consumed with conn_consume_outgoing.
*/
conn_should_close :: proc "contextless" (c: ^Conn) -> bool {
	return c.state == .Closed && c.out_pos >= len(c.outbound)
}

// Drops consumed input and the previous reassembled message. Invalidates borrowed event data.
@(private)
conn_reclaim :: proc(c: ^Conn) {
	if c.message_ready {
		clear(&c.message)
		c.message_ready = false
	}
	if c.in_pos == 0 {
		return
	}
	if c.in_pos >= len(c.inbound) {
		clear(&c.inbound)
		c.in_pos = 0
	} else if c.in_pos >= 4096 || c.in_pos * 2 >= len(c.inbound) {
		remove_range(&c.inbound, 0, c.in_pos)
		c.in_pos = 0
	}
}

/*
conn_receive appends bytes read from the transport. It doesn't parse them;
call conn_next_event until it returns a nil event.

Data that arrives after a close frame was received, or after the connection
failed, is dropped.

Returns an allocator error, or nil.
*/
conn_receive :: proc(c: ^Conn, data: []byte) -> Error {
	conn_reclaim(c)
	if c.close_received || c.failed {
		return nil
	}
	_ = append(&c.inbound, ..data) or_return
	return nil
}

/*
conn_next_event parses the next event out of the bytes received so far.

Returns:
- event: a Message, Ping, Pong or Close, or nil when a full frame isn't
  buffered yet. Event data borrows Conn memory until the next call to
  conn_receive or conn_next_event.
- err: a protocol violation. The Conn has then queued a close frame with the
  matching code (1002, 1007 or 1009) and moved to `.Closed`; flush
  conn_outgoing and close the transport.
*/
conn_next_event :: proc(c: ^Conn) -> (event: Event, err: Error) {
	conn_reclaim(c)
	for {
		if c.close_received || c.failed {
			return nil, nil
		}
		avail := c.inbound[c.in_pos:]
		h, hsize, ferr := decode_header(avail)
		if ferr == .Incomplete {
			return nil, nil
		}
		if ferr != .None {
			return nil, conn_fail(c, .Protocol_Error, ferr)
		}
		if c.role == .Server && !h.masked {
			return nil, conn_fail(c, .Protocol_Error, Conn_Error.Unmasked_Frame)
		}
		if c.role == .Client && h.masked {
			return nil, conn_fail(c, .Protocol_Error, Conn_Error.Masked_Frame)
		}
		limit := u64(c.config.max_message_size)
		if h.payload_len > limit {
			return nil, conn_fail(c, .Message_Too_Big, Conn_Error.Message_Too_Big)
		}
		if h.opcode == .Continuation && c.in_message && u64(len(c.message)) + h.payload_len > limit {
			return nil, conn_fail(c, .Message_Too_Big, Conn_Error.Message_Too_Big)
		}
		if u64(len(avail) - hsize) < h.payload_len {
			return nil, nil
		}

		n := int(h.payload_len)
		payload := avail[hsize:hsize + n]
		if h.masked {
			apply_mask(payload, h.mask_key)
		}
		c.in_pos += hsize + n

		switch h.opcode {
		case .Ping:
			if !c.config.manual_pong && !c.close_sent {
				send_frame(c, .Pong, true, payload) or_return
			}
			return Ping{payload}, nil

		case .Pong:
			return Pong{payload}, nil

		case .Close:
			code, reason, cerr := decode_close_payload(payload)
			if cerr != .None {
				fail_code: Close_Code = cerr == .Invalid_Utf8_Reason ? .Invalid_Payload : .Protocol_Error
				return nil, conn_fail(c, fail_code, cerr)
			}
			c.close_received = true
			if !c.close_sent {
				conn_queue_close(c, code, "") or_return
			}
			c.state = .Closed
			return Close{code, reason}, nil

		case .Text, .Binary:
			if c.in_message {
				return nil, conn_fail(c, .Protocol_Error, Conn_Error.Expected_Continuation)
			}
			kind: Message_Kind = h.opcode == .Text ? .Text : .Binary
			if h.fin {
				if kind == .Text && !valid_utf8(payload) {
					return nil, conn_fail(c, .Invalid_Payload, Conn_Error.Invalid_Utf8)
				}
				return Message{kind, payload}, nil
			}
			c.in_message = true
			c.message_kind = kind
			utf8_reset(&c.utf8)
			if kind == .Text && !utf8_feed(&c.utf8, payload) {
				return nil, conn_fail(c, .Invalid_Payload, Conn_Error.Invalid_Utf8)
			}
			_ = append(&c.message, ..payload) or_return

		case .Continuation:
			if !c.in_message {
				return nil, conn_fail(c, .Protocol_Error, Conn_Error.Unexpected_Continuation)
			}
			if c.message_kind == .Text && !utf8_feed(&c.utf8, payload) {
				return nil, conn_fail(c, .Invalid_Payload, Conn_Error.Invalid_Utf8)
			}
			_ = append(&c.message, ..payload) or_return
			if h.fin {
				if c.message_kind == .Text && !utf8_finish(&c.utf8) {
					return nil, conn_fail(c, .Invalid_Payload, Conn_Error.Invalid_Utf8)
				}
				c.in_message = false
				c.message_ready = true
				return Message{c.message_kind, c.message[:]}, nil
			}
		}
	}
}

// Queues a close frame with `code` if none was sent, marks the Conn failed and returns `err`.
@(private)
conn_fail :: proc(c: ^Conn, code: Close_Code, err: Error) -> Error {
	if !c.close_sent {
		_ = conn_queue_close(c, code, "")
	}
	c.failed = true
	c.in_message = false
	c.state = .Closed
	return err
}

@(private)
conn_queue_close :: proc(c: ^Conn, code: Close_Code, reason: string) -> Error {
	buf: [MAX_CONTROL_PAYLOAD]byte
	n := encode_close_payload(buf[:], code, reason) or_return
	send_frame(c, .Close, true, buf[:n]) or_return
	c.close_sent = true
	c.sent_code = code
	return nil
}

@(private)
next_mask_key :: proc(c: ^Conn) -> (key: [4]byte) {
	if c.config.mask_key_proc != nil {
		return c.config.mask_key_proc(c.config.mask_key_data)
	}
	when crypto.HAS_RAND_BYTES {
		crypto.rand_bytes(key[:])
	} else {
		// No entropy source on this target: fall back to xorshift. Supply
		// Config.mask_key_proc here if the network path has intermediaries.
		x := c.mask_state
		x ~= x << 13
		x ~= x >> 7
		x ~= x << 17
		c.mask_state = x
		key = transmute([4]byte)u32(x >> 16)
	}
	return
}

@(private)
send_frame :: proc(c: ^Conn, op: Opcode, fin: bool, payload: []byte) -> Error {
	if c.out_pos > 0 && c.out_pos * 2 >= len(c.outbound) {
		remove_range(&c.outbound, 0, c.out_pos)
		c.out_pos = 0
	}
	h := Frame_Header {
		fin    = fin,
		opcode = op,
	}
	if c.role == .Client {
		h.masked = true
		h.mask_key = next_mask_key(c)
	}
	return append_frame(&c.outbound, h, payload)
}

/*
conn_outgoing returns the bytes queued for the transport. Write as many as
the transport accepts, then report them with conn_consume_outgoing. The
slice stays valid until the next call that queues or consumes data.
*/
conn_outgoing :: proc "contextless" (c: ^Conn) -> []byte {
	return c.outbound[c.out_pos:]
}

// conn_consume_outgoing marks the first `n` bytes of conn_outgoing as written.
conn_consume_outgoing :: proc(c: ^Conn, n: int) {
	c.out_pos = min(c.out_pos + max(n, 0), len(c.outbound))
	if c.out_pos == len(c.outbound) {
		clear(&c.outbound)
		c.out_pos = 0
	}
}

/*
conn_send_message queues a data message, split into fragments when
Config.fragment_size is positive.

Returns:
- `Conn_Error.Closed` once this side sent a close frame.
- `Conn_Error.Invalid_Utf8` when a text message isn't valid UTF-8.
- an allocator error.
*/
conn_send_message :: proc(c: ^Conn, kind: Message_Kind, data: []byte) -> Error {
	if c.close_sent || c.failed {
		return Conn_Error.Closed
	}
	if kind == .Text && !valid_utf8(data) {
		return Conn_Error.Invalid_Utf8
	}
	first: Opcode = kind == .Text ? .Text : .Binary
	frag := c.config.fragment_size
	if frag <= 0 || len(data) <= frag {
		return send_frame(c, first, true, data)
	}
	op := first
	for start := 0; start < len(data); start += frag {
		end := min(start + frag, len(data))
		send_frame(c, op, end == len(data), data[start:end]) or_return
		op = .Continuation
	}
	return nil
}

// conn_send_text queues a text message. See conn_send_message for errors.
conn_send_text :: proc(c: ^Conn, text: string) -> Error {
	return conn_send_message(c, .Text, transmute([]byte)text)
}

// conn_send_binary queues a binary message. See conn_send_message for errors.
conn_send_binary :: proc(c: ^Conn, data: []byte) -> Error {
	return conn_send_message(c, .Binary, data)
}

/*
conn_send_ping queues a ping with up to 125 bytes of payload.

Returns `Conn_Error.Closed`, `Frame_Error.Control_Frame_Too_Long` or an
allocator error.
*/
conn_send_ping :: proc(c: ^Conn, payload: []byte = nil) -> Error {
	if c.close_sent || c.failed {
		return Conn_Error.Closed
	}
	if len(payload) > MAX_CONTROL_PAYLOAD {
		return Frame_Error.Control_Frame_Too_Long
	}
	return send_frame(c, .Ping, true, payload)
}

/*
conn_send_pong queues a pong with up to 125 bytes of payload. Use it with
Config.manual_pong, or as a one-way heartbeat.

Returns `Conn_Error.Closed`, `Frame_Error.Control_Frame_Too_Long` or an
allocator error.
*/
conn_send_pong :: proc(c: ^Conn, payload: []byte = nil) -> Error {
	if c.close_sent || c.failed {
		return Conn_Error.Closed
	}
	if len(payload) > MAX_CONTROL_PAYLOAD {
		return Frame_Error.Control_Frame_Too_Long
	}
	return send_frame(c, .Pong, true, payload)
}

/*
conn_close starts the closing handshake by queuing a close frame. The state
becomes `.Closing` until the peer's close frame arrives through
conn_next_event. Pass `.No_Status` to send a close frame with no payload.

Returns:
- `Conn_Error.Closed` when a close frame was already sent.
- a `Close_Error` when `code` can't be sent or `reason` is too long or not UTF-8.
- an allocator error.
*/
conn_close :: proc(c: ^Conn, code := Close_Code.Normal, reason := "") -> Error {
	if c.close_sent || c.failed {
		return Conn_Error.Closed
	}
	conn_queue_close(c, code, reason) or_return
	c.state = c.close_received ? .Closed : .Closing
	return nil
}
