// Package websocket_tests holds the unit tests for websocket. Run them with `odin test tests`.
package websocket_tests

import ws ".."
import "core:strings"
import "core:testing"

// RFC 6455 section 1.3 example key and accept value.
RFC_KEY :: "dGhlIHNhbXBsZSBub25jZQ=="
RFC_ACCEPT :: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

@(test)
test_accept_key_matches_rfc_example :: proc(t: ^testing.T) {
	accept := ws.accept_key(RFC_KEY)
	testing.expect_value(t, string(accept[:]), RFC_ACCEPT)
}

@(test)
test_accept_key_second_known_vector :: proc(t: ^testing.T) {
	// Example from RFC 6455 section 4.1 / MDN.
	accept := ws.accept_key("x3JJHMbDL1EzLkh9GBhXDw==")
	testing.expect_value(t, string(accept[:]), "HSmrc0sMlYUkAGmm5OPpG2HaGWk=")
}

@(test)
test_generate_key_encodes_rfc_nonce :: proc(t: ^testing.T) {
	nonce: [16]byte
	copy(nonce[:], "the sample nonce")
	key := ws.generate_key(nonce)
	testing.expect_value(t, string(key[:]), RFC_KEY)
}

@(test)
test_new_key_is_valid_and_random :: proc(t: ^testing.T) {
	a, ok_a := ws.new_key()
	b, ok_b := ws.new_key()
	testing.expect(t, ok_a && ok_b)
	testing.expect(t, ws.is_valid_key(string(a[:])))
	testing.expect(t, ws.is_valid_key(string(b[:])))
	testing.expect(t, a != b, "two random keys should differ")
}

@(test)
test_is_valid_key_accepts_rfc_key_with_spaces :: proc(t: ^testing.T) {
	testing.expect(t, ws.is_valid_key(RFC_KEY))
	testing.expect(t, ws.is_valid_key("  " + RFC_KEY + "\t"))
}

@(test)
test_is_valid_key_rejects_malformed_keys :: proc(t: ^testing.T) {
	bad := []string {
		"",
		"dGhlIHNhbXBsZSBub25jZQ", // missing padding
		"dGhlIHNhbXBsZSBub25jZQ=", // short
		"dGhlIHNhbXBsZSBub25jZQ===", // long
		"dGhlIHNhbXBsZSBub25jZ*==", // bad symbol
		"dGhlIHNhbXBsZSBub25jZR==", // non-canonical trailing bits
		"dGhlIHNhbXBsZSBub25jZQ.=",
	}
	for k in bad {
		testing.expectf(t, !ws.is_valid_key(k), "key %q should be rejected", k)
	}
}

@(test)
test_header_has_token_is_case_insensitive_list_match :: proc(t: ^testing.T) {
	testing.expect(t, ws.header_has_token("Upgrade", "upgrade"))
	testing.expect(t, ws.header_has_token("keep-alive, Upgrade", "Upgrade"))
	testing.expect(t, ws.header_has_token(" keep-alive ,\tUPGRADE ", "upgrade"))
	testing.expect(t, !ws.header_has_token("keep-alive", "Upgrade"))
	testing.expect(t, !ws.header_has_token("Upgraded", "Upgrade"), "partial words don't count")
	testing.expect(t, !ws.header_has_token("", "Upgrade"))
}

@(private = "file")
good_request :: proc() -> ws.Client_Request {
	return {
		method = "GET",
		upgrade = "websocket",
		connection = "keep-alive, Upgrade",
		key = RFC_KEY,
		version = "13",
	}
}

@(test)
test_validate_client_request_accepts_valid_request :: proc(t: ^testing.T) {
	testing.expect_value(t, ws.validate_client_request(good_request()), ws.Handshake_Error.None)
}

@(test)
test_validate_client_request_reports_each_failure :: proc(t: ^testing.T) {
	r := good_request()
	r.method = "POST"
	testing.expect_value(t, ws.validate_client_request(r), ws.Handshake_Error.Invalid_Method)

	r = good_request()
	r.upgrade = "h2c"
	testing.expect_value(t, ws.validate_client_request(r), ws.Handshake_Error.Missing_Upgrade)

	r = good_request()
	r.connection = "close"
	testing.expect_value(t, ws.validate_client_request(r), ws.Handshake_Error.Missing_Connection)

	r = good_request()
	r.key = ""
	testing.expect_value(t, ws.validate_client_request(r), ws.Handshake_Error.Missing_Key)

	r = good_request()
	r.key = "short=="
	testing.expect_value(t, ws.validate_client_request(r), ws.Handshake_Error.Invalid_Key)

	r = good_request()
	r.version = "8"
	testing.expect_value(t, ws.validate_client_request(r), ws.Handshake_Error.Unsupported_Version)
}

@(test)
test_select_subprotocol_prefers_server_order :: proc(t: ^testing.T) {
	p, ok := ws.select_subprotocol("chat, superchat", {"superchat", "chat"})
	testing.expect(t, ok)
	testing.expect_value(t, p, "superchat")

	_, ok = ws.select_subprotocol("mqtt", {"chat"})
	testing.expect(t, !ok)

	_, ok = ws.select_subprotocol("", {"chat"})
	testing.expect(t, !ok)
}

@(test)
test_server_response_contains_accept_and_protocol :: proc(t: ^testing.T) {
	resp, err := ws.server_response(RFC_KEY, "chat")
	defer delete(resp)
	testing.expect_value(t, err, nil)
	expected :=
		"HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
		"Sec-WebSocket-Protocol: chat\r\n" +
		"\r\n"
	testing.expect_value(t, resp, expected)
}

@(test)
test_server_response_omits_empty_protocol :: proc(t: ^testing.T) {
	resp, err := ws.server_response(RFC_KEY)
	defer delete(resp)
	testing.expect_value(t, err, nil)
	testing.expect(t, !strings.contains(resp, "Sec-WebSocket-Protocol"))
	testing.expect(t, strings.has_suffix(resp, "\r\n\r\n"))
}

@(test)
test_client_request_has_required_headers :: proc(t: ^testing.T) {
	req, err := ws.client_request("server.example.com", "/chat", RFC_KEY, "chat, superchat")
	defer delete(req)
	testing.expect_value(t, err, nil)
	expected :=
		"GET /chat HTTP/1.1\r\n" +
		"Host: server.example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: chat, superchat\r\n" +
		"\r\n"
	testing.expect_value(t, req, expected)
}

@(test)
test_client_request_defaults_empty_path_to_root :: proc(t: ^testing.T) {
	req, err := ws.client_request("h", "", RFC_KEY)
	defer delete(req)
	testing.expect_value(t, err, nil)
	testing.expect(t, strings.has_prefix(req, "GET / HTTP/1.1\r\n"))
}

@(test)
test_validate_server_response :: proc(t: ^testing.T) {
	testing.expect_value(t, ws.validate_server_response(101, "websocket", "Upgrade", RFC_ACCEPT, RFC_KEY), ws.Handshake_Error.None)
	testing.expect_value(t, ws.validate_server_response(200, "websocket", "Upgrade", RFC_ACCEPT, RFC_KEY), ws.Handshake_Error.Unexpected_Status)
	testing.expect_value(t, ws.validate_server_response(101, "", "Upgrade", RFC_ACCEPT, RFC_KEY), ws.Handshake_Error.Missing_Upgrade)
	testing.expect_value(t, ws.validate_server_response(101, "websocket", "", RFC_ACCEPT, RFC_KEY), ws.Handshake_Error.Missing_Connection)
	testing.expect_value(t, ws.validate_server_response(101, "websocket", "Upgrade", "AAAA", RFC_KEY), ws.Handshake_Error.Accept_Mismatch)
}
