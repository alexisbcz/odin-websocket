package websocket_tests

import ws ".."
import "core:slice"
import "core:testing"

// Appends one client-to-server (masked) frame to `out`.
@(private = "file")
client_frame :: proc(out: ^[dynamic]byte, op: ws.Opcode, payload: []byte, fin := true) {
	frame, _ := ws.encode_frame({fin = fin, opcode = op, masked = true, mask_key = RFC_MASK}, payload)
	defer delete(frame)
	append(out, ..frame)
}

// Appends one server-to-client (unmasked) frame to `out`.
@(private = "file")
server_frame :: proc(out: ^[dynamic]byte, op: ws.Opcode, payload: []byte, fin := true) {
	frame, _ := ws.encode_frame({fin = fin, opcode = op}, payload)
	defer delete(frame)
	append(out, ..frame)
}

@(private = "file")
fixed_mask :: proc(_: rawptr) -> [4]byte {
	return RFC_MASK
}

@(private = "file")
b :: proc(s: string) -> []byte {
	return transmute([]byte)s
}

// Decodes the single frame at the start of `data`, unmasking a copy of its payload.
@(private = "file")
first_frame :: proc(data: []byte) -> (h: ws.Frame_Header, payload: []byte, ok: bool) {
	hdr, size, err := ws.decode_header(data)
	if err != .None || u64(len(data) - size) < hdr.payload_len {
		return {}, nil, false
	}
	payload = slice.clone(data[size:size + int(hdr.payload_len)])
	if hdr.masked {
		ws.apply_mask(payload, hdr.mask_key)
	}
	return hdr, payload, true
}

// Expects the outgoing queue to start with a close frame carrying `code`.
@(private = "file")
expect_close_sent :: proc(t: ^testing.T, c: ^ws.Conn, code: ws.Close_Code, loc := #caller_location) {
	h, payload, ok := first_frame(ws.conn_outgoing(c))
	defer delete(payload)
	testing.expect(t, ok, "no frame queued", loc = loc)
	testing.expect_value(t, h.opcode, ws.Opcode.Close, loc = loc)
	got, _, _ := ws.decode_close_payload(payload)
	testing.expect_value(t, got, code, loc = loc)
}

@(test)
test_server_receives_rfc_masked_hello :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	testing.expect_value(t, ws.conn_receive(&c, {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}), nil)
	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	msg, ok := ev.(ws.Message)
	testing.expect(t, ok)
	testing.expect_value(t, msg.kind, ws.Message_Kind.Text)
	testing.expect_value(t, ws.message_text(msg), "Hello")

	ev2, err2 := ws.conn_next_event(&c)
	testing.expect_value(t, err2, nil)
	testing.expect(t, ev2 == nil)
}

@(test)
test_client_receives_rfc_unmasked_hello :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f})
	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	msg, ok := ev.(ws.Message)
	testing.expect(t, ok)
	testing.expect_value(t, ws.message_text(msg), "Hello")
}

@(test)
test_server_rejects_unmasked_frame :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f})
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Unmasked_Frame))
	testing.expect_value(t, ws.conn_state(&c), ws.State.Closed)
	expect_close_sent(t, &c, .Protocol_Error)
}

@(test)
test_client_rejects_masked_frame :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client, {mask_key_proc = fixed_mask})
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58})
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Masked_Frame))
	expect_close_sent(t, &c, .Protocol_Error)
}

@(test)
test_reassembles_fragmented_text :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	// RFC 6455 section 5.7: "Hel" + "lo".
	_ = ws.conn_receive(&c, {0x01, 0x03, 0x48, 0x65, 0x6c, 0x80, 0x02, 0x6c, 0x6f})
	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	msg, ok := ev.(ws.Message)
	testing.expect(t, ok)
	testing.expect_value(t, ws.message_text(msg), "Hello")
}

@(test)
test_reassembles_many_binary_fragments :: proc(t: ^testing.T) {
	// Autobahn 5.x: a binary message in many fragments, including empty ones.
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	client_frame(&wire, .Binary, {1, 2}, fin = false)
	client_frame(&wire, .Continuation, {}, fin = false)
	client_frame(&wire, .Continuation, {3}, fin = false)
	client_frame(&wire, .Continuation, {4, 5, 6}, fin = true)
	_ = ws.conn_receive(&c, wire[:])

	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	msg := ev.(ws.Message)
	testing.expect_value(t, msg.kind, ws.Message_Kind.Binary)
	testing.expect(t, slice.equal(msg.data, []byte{1, 2, 3, 4, 5, 6}))
}

@(test)
test_ping_between_fragments_is_delivered_first :: proc(t: ^testing.T) {
	// Autobahn 5.6 to 5.8: control frames may interleave with fragments.
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	client_frame(&wire, .Text, b("frag"), fin = false)
	client_frame(&wire, .Ping, b("hi"))
	client_frame(&wire, .Continuation, b("ment"), fin = true)
	_ = ws.conn_receive(&c, wire[:])

	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	ping, is_ping := ev.(ws.Ping)
	testing.expect(t, is_ping)
	testing.expect_value(t, string(ping.payload), "hi")

	ev, err = ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	msg, is_msg := ev.(ws.Message)
	testing.expect(t, is_msg)
	testing.expect_value(t, ws.message_text(msg), "fragment")
}

@(test)
test_auto_pong_echoes_ping_payload :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	// RFC 6455 section 5.7: unmasked ping is invalid from a client, so mask it.
	wire: [dynamic]byte
	defer delete(wire)
	client_frame(&wire, .Ping, b("Hello"))
	_ = ws.conn_receive(&c, wire[:])
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)

	// A server sends the pong unmasked: 0x8A 0x05 "Hello".
	testing.expect(t, slice.equal(ws.conn_outgoing(&c), []byte{0x8a, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}))
}

@(test)
test_manual_pong_suppresses_auto_reply :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Server, {manual_pong = true})
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	client_frame(&wire, .Ping, b("x"))
	_ = ws.conn_receive(&c, wire[:])
	ev, _ := ws.conn_next_event(&c)
	_, is_ping := ev.(ws.Ping)
	testing.expect(t, is_ping)
	testing.expect_value(t, len(ws.conn_outgoing(&c)), 0)

	testing.expect_value(t, ws.conn_send_pong(&c, b("x")), nil)
	testing.expect(t, slice.equal(ws.conn_outgoing(&c), []byte{0x8a, 0x01, 'x'}))
}

@(test)
test_pong_event_is_reported :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x8a, 0x02, 'o', 'k'})
	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	pong, ok := ev.(ws.Pong)
	testing.expect(t, ok)
	testing.expect_value(t, string(pong.payload), "ok")
	testing.expect_value(t, len(ws.conn_outgoing(&c)), 0)
}

@(test)
test_unexpected_continuation_fails_connection :: proc(t: ^testing.T) {
	// Autobahn 5.9: a continuation with no message started.
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x80, 0x01, 'x'})
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Unexpected_Continuation))
	expect_close_sent(t, &c, .Protocol_Error)
}

@(test)
test_new_message_during_fragments_fails_connection :: proc(t: ^testing.T) {
	// Autobahn 5.18: text frame while a fragmented text is still open.
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	server_frame(&wire, .Text, b("a"), fin = false)
	server_frame(&wire, .Text, b("b"), fin = true)
	_ = ws.conn_receive(&c, wire[:])
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Expected_Continuation))
	expect_close_sent(t, &c, .Protocol_Error)
}

@(test)
test_invalid_utf8_text_fails_with_1007 :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	server_frame(&wire, .Text, {0xCE, 0xBA, 0xED, 0xA0, 0x80})
	_ = ws.conn_receive(&c, wire[:])
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Invalid_Utf8))
	expect_close_sent(t, &c, .Invalid_Payload)
}

@(test)
test_invalid_utf8_detected_in_first_fragment :: proc(t: ^testing.T) {
	// Autobahn 6.4.1: fail fast before the final fragment arrives.
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	server_frame(&wire, .Text, {0xF4, 0x90, 0x80, 0x80}, fin = false)
	_ = ws.conn_receive(&c, wire[:])
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Invalid_Utf8))
}

@(test)
test_utf8_split_across_fragments_is_accepted :: proc(t: ^testing.T) {
	// Autobahn 6.2.3: a code point split between frames.
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	text := b("κόσμε")
	wire: [dynamic]byte
	defer delete(wire)
	server_frame(&wire, .Text, text[:3], fin = false)
	server_frame(&wire, .Continuation, text[3:], fin = true)
	_ = ws.conn_receive(&c, wire[:])
	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, ws.message_text(ev.(ws.Message)), "κόσμε")
}

@(test)
test_truncated_utf8_at_message_end_fails :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	server_frame(&wire, .Text, {'o', 0xE2}, fin = false)
	server_frame(&wire, .Continuation, {0x82}, fin = true)
	_ = ws.conn_receive(&c, wire[:])
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Invalid_Utf8))
}

@(test)
test_binary_message_skips_utf8_check :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x82, 0x02, 0xFF, 0xFE})
	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	testing.expect(t, slice.equal(ev.(ws.Message).data, []byte{0xFF, 0xFE}))
}

@(test)
test_peer_close_is_echoed :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	payload: [32]byte
	n, _ := ws.encode_close_payload(payload[:], .Going_Away, "bye")
	wire: [dynamic]byte
	defer delete(wire)
	client_frame(&wire, .Close, payload[:n])
	_ = ws.conn_receive(&c, wire[:])

	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	cl, ok := ev.(ws.Close)
	testing.expect(t, ok)
	testing.expect_value(t, cl.code, ws.Close_Code.Going_Away)
	testing.expect_value(t, cl.reason, "bye")
	testing.expect_value(t, ws.conn_state(&c), ws.State.Closed)
	expect_close_sent(t, &c, .Going_Away)

	testing.expect(t, !ws.conn_should_close(&c), "output still pending")
	ws.conn_consume_outgoing(&c, len(ws.conn_outgoing(&c)))
	testing.expect(t, ws.conn_should_close(&c))
}

@(test)
test_empty_close_is_echoed_empty :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x88, 0x00})
	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, ev.(ws.Close).code, ws.Close_Code.No_Status)
	h, payload, ok := first_frame(ws.conn_outgoing(&c))
	defer delete(payload)
	testing.expect(t, ok)
	testing.expect_value(t, h.opcode, ws.Opcode.Close)
	testing.expect_value(t, len(payload), 0)
}

@(test)
test_local_close_waits_for_peer :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client, {mask_key_proc = fixed_mask})
	defer ws.conn_destroy(&c)

	testing.expect_value(t, ws.conn_close(&c, .Normal, "done"), nil)
	testing.expect_value(t, ws.conn_state(&c), ws.State.Closing)
	h, payload, ok := first_frame(ws.conn_outgoing(&c))
	defer delete(payload)
	testing.expect(t, ok)
	testing.expect(t, h.masked)
	code, reason, _ := ws.decode_close_payload(payload)
	testing.expect_value(t, code, ws.Close_Code.Normal)
	testing.expect_value(t, reason, "done")
	ws.conn_consume_outgoing(&c, len(ws.conn_outgoing(&c)))

	// Data still flows in while closing; then the peer's close completes it.
	_ = ws.conn_receive(&c, {0x81, 0x01, 'z', 0x88, 0x02, 0x03, 0xE8})
	ev, _ := ws.conn_next_event(&c)
	testing.expect_value(t, ws.message_text(ev.(ws.Message)), "z")
	ev, _ = ws.conn_next_event(&c)
	testing.expect_value(t, ev.(ws.Close).code, ws.Close_Code.Normal)
	testing.expect_value(t, ws.conn_state(&c), ws.State.Closed)
	testing.expect_value(t, len(ws.conn_outgoing(&c)), 0)
	testing.expect(t, ws.conn_should_close(&c))
}

@(test)
test_send_after_close_returns_closed :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	testing.expect_value(t, ws.conn_close(&c), nil)
	closed := ws.Error(ws.Conn_Error.Closed)
	testing.expect_value(t, ws.conn_send_text(&c, "late"), closed)
	testing.expect_value(t, ws.conn_send_binary(&c, {1}), closed)
	testing.expect_value(t, ws.conn_send_ping(&c), closed)
	testing.expect_value(t, ws.conn_send_pong(&c), closed)
	testing.expect_value(t, ws.conn_close(&c), closed)
}

@(test)
test_invalid_close_code_fails_with_1002 :: proc(t: ^testing.T) {
	// Autobahn 7.9.1: close code 0.
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x88, 0x02, 0x00, 0x00})
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Close_Error.Invalid_Code))
	expect_close_sent(t, &c, .Protocol_Error)
}

@(test)
test_close_reason_bad_utf8_fails_with_1007 :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x88, 0x03, 0x03, 0xE8, 0xFF})
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Close_Error.Invalid_Utf8_Reason))
	expect_close_sent(t, &c, .Invalid_Payload)
}

@(test)
test_frame_errors_fail_with_1002 :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x83, 0x00}) // reserved opcode 3
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Frame_Error.Reserved_Opcode))
	expect_close_sent(t, &c, .Protocol_Error)
}

@(test)
test_frames_after_close_are_ignored :: proc(t: ^testing.T) {
	// Autobahn 7.1.x: nothing is processed after the close frame.
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x88, 0x00, 0x81, 0x01, 'x'})
	ev, _ := ws.conn_next_event(&c)
	_, is_close := ev.(ws.Close)
	testing.expect(t, is_close)
	_ = ws.conn_receive(&c, {0x81, 0x01, 'y'})
	ev2, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	testing.expect(t, ev2 == nil)
}

@(test)
test_message_too_big_fails_with_1009 :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client, {max_message_size = 8})
	defer ws.conn_destroy(&c)

	// Rejected from the header alone, before the payload arrives.
	_ = ws.conn_receive(&c, {0x82, 0x09})
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Message_Too_Big))
	expect_close_sent(t, &c, .Message_Too_Big)
}

@(test)
test_fragmented_message_too_big_fails :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client, {max_message_size = 8})
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	server_frame(&wire, .Binary, {1, 2, 3, 4, 5}, fin = false)
	server_frame(&wire, .Continuation, {6, 7, 8, 9}, fin = true)
	_ = ws.conn_receive(&c, wire[:])
	_, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, ws.Error(ws.Conn_Error.Message_Too_Big))
}

@(test)
test_byte_at_a_time_delivery :: proc(t: ^testing.T) {
	// Autobahn 1.1.x and 1.2.x with chopped delivery.
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	payload := make([]byte, 300)
	defer delete(payload)
	for &x, i in payload {
		x = byte(i)
	}
	wire: [dynamic]byte
	defer delete(wire)
	client_frame(&wire, .Binary, payload[:150], fin = false)
	client_frame(&wire, .Continuation, payload[150:], fin = true)

	got := 0
	for i in 0 ..< len(wire) {
		_ = ws.conn_receive(&c, wire[i:i + 1])
		ev, err := ws.conn_next_event(&c)
		testing.expect_value(t, err, nil)
		if msg, ok := ev.(ws.Message); ok {
			got += 1
			testing.expect_value(t, i, len(wire) - 1)
			testing.expect(t, slice.equal(msg.data, payload))
		}
	}
	testing.expect_value(t, got, 1)
}

@(test)
test_many_messages_in_one_read :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	wire: [dynamic]byte
	defer delete(wire)
	for _ in 0 ..< 100 {
		server_frame(&wire, .Text, b("msg"))
	}
	_ = ws.conn_receive(&c, wire[:])
	count := 0
	for {
		ev, err := ws.conn_next_event(&c)
		testing.expect_value(t, err, nil)
		if ev == nil {
			break
		}
		testing.expect_value(t, ws.message_text(ev.(ws.Message)), "msg")
		count += 1
	}
	testing.expect_value(t, count, 100)
}

@(test)
test_empty_text_message :: proc(t: ^testing.T) {
	// Autobahn 1.1.1: a text message with no payload.
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_receive(&c, {0x81, 0x00})
	ev, err := ws.conn_next_event(&c)
	testing.expect_value(t, err, nil)
	msg := ev.(ws.Message)
	testing.expect_value(t, msg.kind, ws.Message_Kind.Text)
	testing.expect_value(t, len(msg.data), 0)
}

@(test)
test_client_masks_outgoing_frames :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client, {mask_key_proc = fixed_mask})
	defer ws.conn_destroy(&c)

	testing.expect_value(t, ws.conn_send_text(&c, "Hello"), nil)
	// Matches the masked "Hello" example from RFC 6455 section 5.7.
	expected := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	testing.expect(t, slice.equal(ws.conn_outgoing(&c), expected))
}

@(test)
test_client_default_masks_are_random :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Client)
	defer ws.conn_destroy(&c)

	_ = ws.conn_send_binary(&c, {})
	_ = ws.conn_send_binary(&c, {})
	out := ws.conn_outgoing(&c)
	testing.expect_value(t, len(out), 12)
	h1, _, _ := ws.decode_header(out[:6])
	h2, _, _ := ws.decode_header(out[6:])
	testing.expect(t, h1.masked && h2.masked)
	testing.expect(t, h1.mask_key != h2.mask_key, "mask keys should differ")
}

@(test)
test_fragment_size_splits_outgoing_messages :: proc(t: ^testing.T) {
	sender: ws.Conn
	ws.conn_init(&sender, .Server, {fragment_size = 4})
	defer ws.conn_destroy(&sender)
	receiver: ws.Conn
	ws.conn_init(&receiver, .Client)
	defer ws.conn_destroy(&receiver)

	testing.expect_value(t, ws.conn_send_text(&sender, "hello world"), nil)
	out := ws.conn_outgoing(&sender)
	h, _, _ := ws.decode_header(out)
	testing.expect(t, !h.fin)
	testing.expect_value(t, h.opcode, ws.Opcode.Text)
	testing.expect_value(t, len(out), 3 * 2 + 11)

	_ = ws.conn_receive(&receiver, out)
	ws.conn_consume_outgoing(&sender, len(out))
	ev, err := ws.conn_next_event(&receiver)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, ws.message_text(ev.(ws.Message)), "hello world")
}

@(test)
test_send_rejects_bad_input :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	testing.expect_value(t, ws.conn_send_text(&c, "\xC0\xAF"), ws.Error(ws.Conn_Error.Invalid_Utf8))
	big: [126]byte
	testing.expect_value(t, ws.conn_send_ping(&c, big[:]), ws.Error(ws.Frame_Error.Control_Frame_Too_Long))
	testing.expect_value(t, ws.conn_send_pong(&c, big[:]), ws.Error(ws.Frame_Error.Control_Frame_Too_Long))
	testing.expect_value(t, ws.conn_close(&c, .No_Status, "why"), ws.Error(ws.Close_Error.Invalid_Code))
	testing.expect_value(t, ws.conn_close(&c, .Abnormal_Closure), ws.Error(ws.Close_Error.Invalid_Code))
	testing.expect_value(t, ws.conn_state(&c), ws.State.Open)
	testing.expect_value(t, len(ws.conn_outgoing(&c)), 0)
}

@(test)
test_partial_output_consumption :: proc(t: ^testing.T) {
	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)

	_ = ws.conn_send_text(&c, "abc")
	_ = ws.conn_send_text(&c, "def")
	testing.expect_value(t, len(ws.conn_outgoing(&c)), 10)
	ws.conn_consume_outgoing(&c, 4)
	testing.expect(t, slice.equal(ws.conn_outgoing(&c), []byte{'c', 0x81, 0x03, 'd', 'e', 'f'}))
	_ = ws.conn_send_text(&c, "g")
	testing.expect(t, slice.equal(ws.conn_outgoing(&c), []byte{'c', 0x81, 0x03, 'd', 'e', 'f', 0x81, 0x01, 'g'}))
	ws.conn_consume_outgoing(&c, 1000)
	testing.expect_value(t, len(ws.conn_outgoing(&c)), 0)
}

@(test)
test_client_server_round_trip :: proc(t: ^testing.T) {
	client, server: ws.Conn
	ws.conn_init(&client, .Client)
	defer ws.conn_destroy(&client)
	ws.conn_init(&server, .Server)
	defer ws.conn_destroy(&server)

	big := make([]byte, 70000)
	defer delete(big)
	for &x, i in big {
		x = byte(i * 7)
	}
	_ = ws.conn_send_binary(&client, big)
	_ = ws.conn_send_text(&client, "after")
	_ = ws.conn_receive(&server, ws.conn_outgoing(&client))
	ws.conn_consume_outgoing(&client, len(ws.conn_outgoing(&client)))

	ev, err := ws.conn_next_event(&server)
	testing.expect_value(t, err, nil)
	testing.expect(t, slice.equal(ev.(ws.Message).data, big))
	ev, err = ws.conn_next_event(&server)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, ws.message_text(ev.(ws.Message)), "after")

	// The server's close reaches the client, which echoes it back.
	_ = ws.conn_close(&server, .Normal, "")
	_ = ws.conn_receive(&client, ws.conn_outgoing(&server))
	ws.conn_consume_outgoing(&server, len(ws.conn_outgoing(&server)))
	ev, err = ws.conn_next_event(&client)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, ev.(ws.Close).code, ws.Close_Code.Normal)

	_ = ws.conn_receive(&server, ws.conn_outgoing(&client))
	ws.conn_consume_outgoing(&client, len(ws.conn_outgoing(&client)))
	ev, err = ws.conn_next_event(&server)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, ev.(ws.Close).code, ws.Close_Code.Normal)
	testing.expect(t, ws.conn_should_close(&client))
	testing.expect(t, ws.conn_should_close(&server))
}
