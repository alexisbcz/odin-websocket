package websocket_tests

import ws ".."
import "core:testing"

@(test)
test_valid_utf8_accepts_well_formed_text :: proc(t: ^testing.T) {
	good := []string {
		"",
		"Hello",
		"κόσμε", // Autobahn 6.2
		"Hello-µ@ßöäüàá-UTF-8!!", // Autobahn 6.5.x
		"\u0080߿ࠀ￿",
		"\U00010000\U0010FFFF",
		"\xEF\xBF\xBF", // U+FFFF, a noncharacter but valid
	}
	for s in good {
		testing.expectf(t, ws.valid_utf8(transmute([]byte)s), "%q should be valid", s)
	}
}

@(test)
test_valid_utf8_rejects_malformed_sequences :: proc(t: ^testing.T) {
	bad := []string {
		"\x80", // lone continuation byte
		"\xBF",
		"\xC0\xAF", // overlong '/'
		"\xC1\xBF",
		"\xE0\x80\xAF", // overlong 3-byte
		"\xF0\x80\x80\xAF", // overlong 4-byte
		"\xED\xA0\x80", // U+D800 surrogate
		"\xED\xBF\xBF", // U+DFFF surrogate
		"\xF4\x90\x80\x80", // U+110000
		"\xF5\x80\x80\x80",
		"\xFE",
		"\xFF",
		"\xCE\xBA\xE1\xBD", // truncated at the end
		"κόσμε\xED\xA0\x80edited",
	}
	for s in bad {
		testing.expectf(t, !ws.valid_utf8(transmute([]byte)s), "%q should be invalid", s)
	}
}

@(test)
test_utf8_validator_accepts_any_split :: proc(t: ^testing.T) {
	text := transmute([]byte)string("κόσμε \U0001F600 ok")
	for split in 0 ..= len(text) {
		v: ws.Utf8_Validator
		ok := ws.utf8_feed(&v, text[:split]) && ws.utf8_feed(&v, text[split:])
		testing.expectf(t, ok && ws.utf8_finish(&v), "split at %d failed", split)
	}
}

@(test)
test_utf8_validator_fails_fast :: proc(t: ^testing.T) {
	// Autobahn 6.4: the bad byte must be caught before the message ends.
	v: ws.Utf8_Validator
	testing.expect(t, ws.utf8_feed(&v, transmute([]byte)string("κόσμε")))
	testing.expect(t, !ws.utf8_feed(&v, {0xF4, 0x90}))
	// Once failed, the validator stays failed.
	testing.expect(t, !ws.utf8_feed(&v, transmute([]byte)string("fine")))
	testing.expect(t, !ws.utf8_finish(&v))
	ws.utf8_reset(&v)
	testing.expect(t, ws.utf8_feed(&v, transmute([]byte)string("fine")))
	testing.expect(t, ws.utf8_finish(&v))
}

@(test)
test_utf8_finish_detects_incomplete_code_point :: proc(t: ^testing.T) {
	v: ws.Utf8_Validator
	testing.expect(t, ws.utf8_feed(&v, {0xF0, 0x9F, 0x98}))
	testing.expect(t, !ws.utf8_finish(&v))
	testing.expect(t, ws.utf8_feed(&v, {0x80}))
	testing.expect(t, ws.utf8_finish(&v))
}

@(test)
test_close_codes_valid_on_wire :: proc(t: ^testing.T) {
	// Autobahn 7.7.x lists codes a peer must accept.
	for c in ([]u16{1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000, 4999}) {
		testing.expectf(t, ws.close_code_is_valid(ws.Close_Code(c)), "%d should be valid", c)
	}
}

@(test)
test_close_codes_invalid_on_wire :: proc(t: ^testing.T) {
	// Autobahn 7.9.x lists codes a peer must reject.
	for c in ([]u16{0, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65535}) {
		testing.expectf(t, !ws.close_code_is_valid(ws.Close_Code(c)), "%d should be invalid", c)
	}
}

@(test)
test_close_payload_round_trip :: proc(t: ^testing.T) {
	buf: [ws.MAX_CONTROL_PAYLOAD]byte
	n, err := ws.encode_close_payload(buf[:], .Going_Away, "server restart")
	testing.expect_value(t, err, nil)
	testing.expect_value(t, n, 2 + len("server restart"))
	testing.expect_value(t, buf[0], 0x03)
	testing.expect_value(t, buf[1], 0xE9)

	code, reason, derr := ws.decode_close_payload(buf[:n])
	testing.expect_value(t, derr, ws.Close_Error.None)
	testing.expect_value(t, code, ws.Close_Code.Going_Away)
	testing.expect_value(t, reason, "server restart")
}

@(test)
test_close_payload_application_code :: proc(t: ^testing.T) {
	buf: [4]byte
	n, err := ws.encode_close_payload(buf[:], ws.Close_Code(4000), "")
	testing.expect_value(t, err, nil)
	code, _, derr := ws.decode_close_payload(buf[:n])
	testing.expect_value(t, derr, ws.Close_Error.None)
	testing.expect_value(t, u16(code), 4000)
}

@(test)
test_decode_close_payload_errors :: proc(t: ^testing.T) {
	code, _, err := ws.decode_close_payload({})
	testing.expect_value(t, err, ws.Close_Error.None)
	testing.expect_value(t, code, ws.Close_Code.No_Status)

	// Autobahn 7.3.2: a 1-byte close payload.
	_, _, err = ws.decode_close_payload({0x03})
	testing.expect_value(t, err, ws.Close_Error.Payload_Too_Short)

	_, _, err = ws.decode_close_payload({0x03, 0xED}) // 1005
	testing.expect_value(t, err, ws.Close_Error.Invalid_Code)

	// Autobahn 7.5.1: a reason with invalid UTF-8.
	_, _, err = ws.decode_close_payload({0x03, 0xE8, 0xCE, 0xBA, 0xED, 0xA0, 0x80})
	testing.expect_value(t, err, ws.Close_Error.Invalid_Utf8_Reason)
}

@(test)
test_encode_close_payload_errors :: proc(t: ^testing.T) {
	buf: [ws.MAX_CONTROL_PAYLOAD]byte
	long_reason: [ws.MAX_CLOSE_REASON + 1]byte
	for &b in long_reason {
		b = 'x'
	}
	_, err := ws.encode_close_payload(buf[:], .Normal, string(long_reason[:]))
	testing.expect_value(t, err, ws.Error(ws.Close_Error.Reason_Too_Long))

	_, err = ws.encode_close_payload(buf[:], .Abnormal_Closure, "")
	testing.expect_value(t, err, ws.Error(ws.Close_Error.Invalid_Code))

	_, err = ws.encode_close_payload(buf[:], .Normal, "\xFF")
	testing.expect_value(t, err, ws.Error(ws.Close_Error.Invalid_Utf8_Reason))

	_, err = ws.encode_close_payload(buf[:3], .Normal, "bye")
	testing.expect_value(t, err, ws.Error(ws.Frame_Error.Buffer_Too_Small))

	n, nerr := ws.encode_close_payload(buf[:], .No_Status, "")
	testing.expect_value(t, nerr, nil)
	testing.expect_value(t, n, 0)
}
