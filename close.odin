package websocket

// MAX_CLOSE_REASON is the longest close reason that fits in a control frame.
MAX_CLOSE_REASON :: MAX_CONTROL_PAYLOAD - 2

/*
Close_Code is the status code carried by a close frame (RFC 6455 section 7.4).

The named members are the codes registered with IANA. Applications may use
any value from 3000 to 4999 by casting, for example `websocket.Close_Code(4000)`.
*/
Close_Code :: enum u16 {
	// The purpose of the connection was fulfilled.
	Normal              = 1000,
	// The endpoint is going away, for example a server shutting down.
	Going_Away          = 1001,
	// The peer broke the protocol.
	Protocol_Error      = 1002,
	// The endpoint received a data type it can't accept.
	Unsupported_Data    = 1003,
	// Reserved: no status code was present. Never sent on the wire.
	No_Status           = 1005,
	// Reserved: the connection closed without a close frame. Never sent on the wire.
	Abnormal_Closure    = 1006,
	// A message contained data inconsistent with its type, such as bad UTF-8.
	Invalid_Payload     = 1007,
	// A message broke the endpoint's policy.
	Policy_Violation    = 1008,
	// A message was too big to process.
	Message_Too_Big     = 1009,
	// The client expected the server to negotiate an extension.
	Mandatory_Extension = 1010,
	// The server hit an unexpected condition.
	Internal_Error      = 1011,
	// The server is restarting.
	Service_Restart     = 1012,
	// The server is overloaded; try again later.
	Try_Again_Later     = 1013,
	// A gateway received an invalid response from upstream.
	Bad_Gateway         = 1014,
	// Reserved: the TLS handshake failed. Never sent on the wire.
	Tls_Handshake       = 1015,
}

/*
close_code_is_valid reports whether `code` may appear in a close frame on the
wire. That covers the registered codes 1000 to 1003 and 1007 to 1014, plus the
3000 to 4999 range for libraries and applications.
*/
close_code_is_valid :: proc "contextless" (code: Close_Code) -> bool {
	switch u16(code) {
	case 1000 ..= 1003, 1007 ..= 1014, 3000 ..= 4999:
		return true
	}
	return false
}

/*
encode_close_payload writes the payload of a close frame to `buf`: a 2-byte
big-endian code followed by `reason`. Pass `.No_Status` to write an empty
payload; `reason` must then be empty too.

Returns:
- n: bytes written, at most 125.
- err: `.Invalid_Code`, `.Reason_Too_Long`, `.Invalid_Utf8_Reason`, or
  `Frame_Error.Buffer_Too_Small`.
*/
encode_close_payload :: proc "contextless" (buf: []byte, code: Close_Code, reason: string) -> (n: int, err: Error) {
	if code == .No_Status {
		if len(reason) != 0 {
			return 0, Close_Error.Invalid_Code
		}
		return 0, nil
	}
	if !close_code_is_valid(code) {
		return 0, Close_Error.Invalid_Code
	}
	if len(reason) > MAX_CLOSE_REASON {
		return 0, Close_Error.Reason_Too_Long
	}
	if !valid_utf8(transmute([]byte)reason) {
		return 0, Close_Error.Invalid_Utf8_Reason
	}
	n = 2 + len(reason)
	if len(buf) < n {
		return 0, Frame_Error.Buffer_Too_Small
	}
	buf[0] = u8(u16(code) >> 8)
	buf[1] = u8(u16(code))
	copy(buf[2:], reason)
	return n, nil
}

/*
decode_close_payload parses the payload of a received close frame.

Returns:
- code: the status code, or `.No_Status` when the payload is empty.
- reason: the reason text; it borrows from `payload`.
- err: `.Payload_Too_Short`, `.Invalid_Code` or `.Invalid_Utf8_Reason`.
*/
decode_close_payload :: proc "contextless" (payload: []byte) -> (code: Close_Code, reason: string, err: Close_Error) {
	switch len(payload) {
	case 0:
		return .No_Status, "", .None
	case 1:
		return .No_Status, "", .Payload_Too_Short
	}
	code = Close_Code(u16(payload[0]) << 8 | u16(payload[1]))
	if !close_code_is_valid(code) {
		return code, "", .Invalid_Code
	}
	rest := payload[2:]
	if !valid_utf8(rest) {
		return code, "", .Invalid_Utf8_Reason
	}
	return code, string(rest), .None
}
