package websocket_tests

import ws ".."
import "core:slice"
import "core:testing"

RFC_MASK :: [4]byte{0x37, 0xfa, 0x21, 0x3d}

@(test)
test_decode_rfc_unmasked_text_frame :: proc(t: ^testing.T) {
	// RFC 6455 section 5.7: a single-frame unmasked text message "Hello".
	data := []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}
	h, size, err := ws.decode_header(data)
	testing.expect_value(t, err, ws.Frame_Error.None)
	testing.expect_value(t, size, 2)
	testing.expect(t, h.fin)
	testing.expect(t, !h.masked)
	testing.expect_value(t, h.opcode, ws.Opcode.Text)
	testing.expect_value(t, h.payload_len, 5)
	testing.expect_value(t, string(data[size:]), "Hello")
}

@(test)
test_decode_rfc_masked_text_frame :: proc(t: ^testing.T) {
	// RFC 6455 section 5.7: a single-frame masked text message "Hello".
	data := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	h, size, err := ws.decode_header(data)
	testing.expect_value(t, err, ws.Frame_Error.None)
	testing.expect_value(t, size, 6)
	testing.expect(t, h.masked)
	testing.expect_value(t, h.mask_key, RFC_MASK)
	payload := data[size:]
	ws.apply_mask(payload, h.mask_key)
	testing.expect_value(t, string(payload), "Hello")
}

@(test)
test_decode_rfc_fragmented_text_frames :: proc(t: ^testing.T) {
	// RFC 6455 section 5.7: "Hel" then "lo".
	first := []byte{0x01, 0x03, 0x48, 0x65, 0x6c}
	second := []byte{0x80, 0x02, 0x6c, 0x6f}
	h1, _, e1 := ws.decode_header(first)
	h2, _, e2 := ws.decode_header(second)
	testing.expect_value(t, e1, ws.Frame_Error.None)
	testing.expect_value(t, e2, ws.Frame_Error.None)
	testing.expect(t, !h1.fin)
	testing.expect_value(t, h1.opcode, ws.Opcode.Text)
	testing.expect(t, h2.fin)
	testing.expect_value(t, h2.opcode, ws.Opcode.Continuation)
}

@(test)
test_decode_rfc_ping_and_masked_pong :: proc(t: ^testing.T) {
	ping := []byte{0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}
	h, _, err := ws.decode_header(ping)
	testing.expect_value(t, err, ws.Frame_Error.None)
	testing.expect_value(t, h.opcode, ws.Opcode.Ping)

	pong := []byte{0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	h2, size, err2 := ws.decode_header(pong)
	testing.expect_value(t, err2, ws.Frame_Error.None)
	testing.expect_value(t, h2.opcode, ws.Opcode.Pong)
	payload := pong[size:]
	ws.apply_mask(payload, h2.mask_key)
	testing.expect_value(t, string(payload), "Hello")
}

@(test)
test_encode_matches_rfc_examples :: proc(t: ^testing.T) {
	unmasked, err := ws.encode_frame({fin = true, opcode = .Text}, transmute([]byte)string("Hello"))
	defer delete(unmasked)
	testing.expect_value(t, err, nil)
	testing.expect(t, slice.equal(unmasked, []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}))

	masked, err2 := ws.encode_frame({fin = true, opcode = .Text, masked = true, mask_key = RFC_MASK}, transmute([]byte)string("Hello"))
	defer delete(masked)
	testing.expect_value(t, err2, nil)
	testing.expect(t, slice.equal(masked, []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}))
}

@(test)
test_encode_256_byte_binary_uses_16_bit_length :: proc(t: ^testing.T) {
	payload := make([]byte, 256)
	defer delete(payload)
	frame, err := ws.encode_frame({fin = true, opcode = .Binary}, payload)
	defer delete(frame)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(frame), 4 + 256)
	testing.expect(t, slice.equal(frame[:4], []byte{0x82, 0x7E, 0x01, 0x00}))
}

@(test)
test_encode_64k_binary_uses_64_bit_length :: proc(t: ^testing.T) {
	payload := make([]byte, 65536)
	defer delete(payload)
	frame, err := ws.encode_frame({fin = true, opcode = .Binary}, payload)
	defer delete(frame)
	testing.expect_value(t, err, nil)
	testing.expect(t, slice.equal(frame[:10], []byte{0x82, 0x7F, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00}))

	h, size, derr := ws.decode_header(frame)
	testing.expect_value(t, derr, ws.Frame_Error.None)
	testing.expect_value(t, size, 10)
	testing.expect_value(t, h.payload_len, 65536)
}

@(test)
test_length_boundaries_round_trip :: proc(t: ^testing.T) {
	buf: [ws.MAX_HEADER_SIZE]byte
	for n in ([]u64{0, 1, 125, 126, 127, 65535, 65536, 1 << 40}) {
		for masked in ([]bool{false, true}) {
			h := ws.Frame_Header{fin = true, opcode = .Binary, masked = masked, payload_len = n}
			if masked {
				h.mask_key = RFC_MASK
			}
			written, eerr := ws.encode_header(buf[:], h)
			testing.expect_value(t, eerr, ws.Frame_Error.None)
			testing.expect_value(t, written, ws.header_size(n, masked))
			back, size, derr := ws.decode_header(buf[:written])
			testing.expect_value(t, derr, ws.Frame_Error.None)
			testing.expect_value(t, size, written)
			testing.expect_value(t, back, h)
		}
	}
}

@(test)
test_decode_reports_incomplete_at_every_prefix :: proc(t: ^testing.T) {
	buf: [ws.MAX_HEADER_SIZE]byte
	h := ws.Frame_Header{fin = true, opcode = .Binary, masked = true, mask_key = RFC_MASK, payload_len = 70000}
	n, _ := ws.encode_header(buf[:], h)
	testing.expect_value(t, n, 14)
	for i in 0 ..< n {
		_, _, err := ws.decode_header(buf[:i])
		testing.expectf(t, err == .Incomplete, "prefix %d: got %v", i, err)
	}
}

@(test)
test_decode_rejects_reserved_bits :: proc(t: ^testing.T) {
	// Autobahn 3.1 to 3.7: RSV1, RSV2 and RSV3 in every combination.
	for bits in ([]byte{0x40, 0x20, 0x10, 0x60, 0x50, 0x30, 0x70}) {
		data := []byte{0x81 | bits, 0x00}
		_, _, err := ws.decode_header(data)
		testing.expect_value(t, err, ws.Frame_Error.Reserved_Bits_Set)
		h, _, err2 := ws.decode_header(data, allow_rsv = true)
		testing.expect_value(t, err2, ws.Frame_Error.None)
		testing.expect(t, h.rsv1 || h.rsv2 || h.rsv3)
	}
}

@(test)
test_decode_rejects_reserved_opcodes :: proc(t: ^testing.T) {
	// Autobahn 4.1 and 4.2: non-control 3 to 7 and control 0xB to 0xF.
	for op in ([]byte{3, 4, 5, 6, 7, 0xB, 0xC, 0xD, 0xE, 0xF}) {
		_, _, err := ws.decode_header({0x80 | op, 0x00})
		testing.expectf(t, err == .Reserved_Opcode, "opcode %x: got %v", op, err)
	}
}

@(test)
test_decode_rejects_fragmented_control_frames :: proc(t: ^testing.T) {
	// Autobahn 5.1 and 5.2: ping and pong with FIN cleared.
	for op in ([]byte{0x8, 0x9, 0xA}) {
		_, _, err := ws.decode_header({op, 0x00})
		testing.expect_value(t, err, ws.Frame_Error.Fragmented_Control_Frame)
	}
}

@(test)
test_decode_rejects_long_control_frames :: proc(t: ^testing.T) {
	// Autobahn 2.5: a ping with 126 bytes of payload.
	_, _, err := ws.decode_header({0x89, 0x7E, 0x00, 0x7E})
	testing.expect_value(t, err, ws.Frame_Error.Control_Frame_Too_Long)
	// 125 bytes is still allowed.
	_, _, ok := ws.decode_header({0x89, 0x7D})
	testing.expect_value(t, ok, ws.Frame_Error.None)
}

@(test)
test_decode_rejects_length_with_top_bit :: proc(t: ^testing.T) {
	_, _, err := ws.decode_header({0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0})
	testing.expect_value(t, err, ws.Frame_Error.Payload_Length_Overflow)
}

@(test)
test_decode_rejects_non_minimal_lengths :: proc(t: ^testing.T) {
	_, _, e16 := ws.decode_header({0x82, 0x7E, 0x00, 0x05})
	testing.expect_value(t, e16, ws.Frame_Error.Non_Minimal_Length)
	_, _, e64 := ws.decode_header({0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF})
	testing.expect_value(t, e64, ws.Frame_Error.Non_Minimal_Length)
}

@(test)
test_encode_header_validates_control_frames :: proc(t: ^testing.T) {
	buf: [ws.MAX_HEADER_SIZE]byte
	_, e1 := ws.encode_header(buf[:], {fin = false, opcode = .Ping})
	testing.expect_value(t, e1, ws.Frame_Error.Fragmented_Control_Frame)
	_, e2 := ws.encode_header(buf[:], {fin = true, opcode = .Close, payload_len = 126})
	testing.expect_value(t, e2, ws.Frame_Error.Control_Frame_Too_Long)
	_, e3 := ws.encode_header(buf[:], {fin = true, opcode = .Binary, payload_len = 1 << 63})
	testing.expect_value(t, e3, ws.Frame_Error.Payload_Length_Overflow)
}

@(test)
test_encode_into_small_buffer_fails :: proc(t: ^testing.T) {
	buf: [6]byte
	_, err := ws.encode_frame_into(buf[:], {fin = true, opcode = .Text}, transmute([]byte)string("Hello"))
	testing.expect_value(t, err, ws.Frame_Error.Buffer_Too_Small)
	_, err2 := ws.encode_header(buf[:1], {fin = true, opcode = .Text})
	testing.expect_value(t, err2, ws.Frame_Error.Buffer_Too_Small)
}

@(test)
test_encode_frame_does_not_modify_payload :: proc(t: ^testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	frame, err := ws.encode_frame({fin = true, opcode = .Binary, masked = true, mask_key = {9, 9, 9, 9}}, payload)
	defer delete(frame)
	testing.expect_value(t, err, nil)
	testing.expect(t, slice.equal(payload, []byte{1, 2, 3, 4, 5}))
	testing.expect(t, !slice.equal(frame[6:], payload))
}

@(test)
test_apply_mask_with_offset_matches_whole_payload :: proc(t: ^testing.T) {
	whole := []byte{10, 20, 30, 40, 50, 60, 70, 80, 90}
	chunked := slice.clone(whole)
	defer delete(chunked)
	ws.apply_mask(whole, RFC_MASK)
	// Unmask in uneven chunks, as bytes would arrive from a socket.
	ws.apply_mask(chunked[0:3], RFC_MASK, 0)
	ws.apply_mask(chunked[3:8], RFC_MASK, 3)
	ws.apply_mask(chunked[8:], RFC_MASK, 8)
	testing.expect(t, slice.equal(whole, chunked))
	ws.apply_mask(whole, RFC_MASK)
	testing.expect(t, slice.equal(whole, []byte{10, 20, 30, 40, 50, 60, 70, 80, 90}))
}

@(test)
test_opcode_is_control :: proc(t: ^testing.T) {
	testing.expect(t, ws.opcode_is_control(.Close))
	testing.expect(t, ws.opcode_is_control(.Ping))
	testing.expect(t, ws.opcode_is_control(.Pong))
	testing.expect(t, !ws.opcode_is_control(.Text))
	testing.expect(t, !ws.opcode_is_control(.Binary))
	testing.expect(t, !ws.opcode_is_control(.Continuation))
}
