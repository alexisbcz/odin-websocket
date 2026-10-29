package websocket

import "core:crypto"
import "core:crypto/legacy/sha1"
import "core:strings"

// GUID is the fixed string that RFC 6455 appends to the client key before hashing.
GUID :: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// KEY_LEN is the length of a Sec-WebSocket-Key value: base64 of 16 bytes.
KEY_LEN :: 24

// ACCEPT_LEN is the length of a Sec-WebSocket-Accept value: base64 of a SHA-1 digest.
ACCEPT_LEN :: 28

// VERSION is the only Sec-WebSocket-Version that RFC 6455 defines.
VERSION :: "13"

@(private, rodata)
BASE64_ALPHABET := [64]byte {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
}

// base64_into writes the padded base64 encoding of `src` to `dst`, which must be large enough.
@(private)
base64_into :: proc "contextless" (dst: []byte, src: []byte) {
	o := 0
	i := 0
	for ; i + 3 <= len(src); i += 3 {
		v := u32(src[i]) << 16 | u32(src[i + 1]) << 8 | u32(src[i + 2])
		dst[o + 0] = BASE64_ALPHABET[v >> 18 & 63]
		dst[o + 1] = BASE64_ALPHABET[v >> 12 & 63]
		dst[o + 2] = BASE64_ALPHABET[v >> 6 & 63]
		dst[o + 3] = BASE64_ALPHABET[v & 63]
		o += 4
	}
	switch len(src) - i {
	case 1:
		v := u32(src[i]) << 16
		dst[o + 0] = BASE64_ALPHABET[v >> 18 & 63]
		dst[o + 1] = BASE64_ALPHABET[v >> 12 & 63]
		dst[o + 2] = '='
		dst[o + 3] = '='
	case 2:
		v := u32(src[i]) << 16 | u32(src[i + 1]) << 8
		dst[o + 0] = BASE64_ALPHABET[v >> 18 & 63]
		dst[o + 1] = BASE64_ALPHABET[v >> 12 & 63]
		dst[o + 2] = BASE64_ALPHABET[v >> 6 & 63]
		dst[o + 3] = '='
	}
}

@(private)
base64_value :: proc "contextless" (c: byte) -> (v: u8, ok: bool) {
	switch c {
	case 'A' ..= 'Z':
		return c - 'A', true
	case 'a' ..= 'z':
		return c - 'a' + 26, true
	case '0' ..= '9':
		return c - '0' + 52, true
	case '+':
		return 62, true
	case '/':
		return 63, true
	}
	return 0, false
}

/*
accept_key computes the Sec-WebSocket-Accept value for a client key: the
base64 encoding of SHA-1(key + GUID), as in RFC 6455 section 4.2.2.

Returns the 28 ASCII bytes of the value. Convert with `string(accept[:])`
after storing the result in a variable.

Example:
	accept := websocket.accept_key("dGhlIHNhbXBsZSBub25jZQ==")
	// string(accept[:]) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
*/
accept_key :: proc(key: string) -> (accept: [ACCEPT_LEN]byte) {
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, transmute([]byte)key)
	sha1.update(&ctx, transmute([]byte)string(GUID))
	digest: [sha1.DIGEST_SIZE]byte
	sha1.final(&ctx, digest[:])
	base64_into(accept[:], digest[:])
	return
}

/*
generate_key returns the Sec-WebSocket-Key value for a 16-byte nonce, which
is its base64 encoding. Use new_key to get a key from a random nonce.
*/
generate_key :: proc "contextless" (nonce: [16]byte) -> (key: [KEY_LEN]byte) {
	n := nonce
	base64_into(key[:], n[:])
	return
}

/*
new_key returns a Sec-WebSocket-Key built from 16 bytes of system entropy.

Returns:
- key: the 24 ASCII bytes of the key.
- ok: false when the platform has no entropy source; `key` is then zero.
*/
new_key :: proc() -> (key: [KEY_LEN]byte, ok: bool) {
	when crypto.HAS_RAND_BYTES {
		nonce: [16]byte
		crypto.rand_bytes(nonce[:])
		return generate_key(nonce), true
	} else {
		return {}, false
	}
}

/*
is_valid_key reports whether `key` is a well-formed Sec-WebSocket-Key: the
canonical base64 encoding of exactly 16 bytes. Surrounding spaces and tabs
are ignored.
*/
is_valid_key :: proc(key: string) -> bool {
	k := strings.trim(key, " \t")
	if len(k) != KEY_LEN || k[22] != '=' || k[23] != '=' {
		return false
	}
	for i in 0 ..< 22 {
		v, ok := base64_value(k[i])
		if !ok {
			return false
		}
		// The last symbol carries 2 data bits; the 4 low bits must be zero.
		if i == 21 && v & 0x0F != 0 {
			return false
		}
	}
	return true
}

/*
header_has_token reports whether the comma-separated header `value` contains
`token`, compared without regard to ASCII case. Use it for headers such as
`Connection: keep-alive, Upgrade`.
*/
header_has_token :: proc(value, token: string) -> bool {
	rest := value
	for part in strings.split_iterator(&rest, ",") {
		if strings.equal_fold(strings.trim(part, " \t"), token) {
			return true
		}
	}
	return false
}

/*
Client_Request holds the header values of an opening handshake request that
a server received. Fill it from whatever HTTP parser you use; missing headers
stay empty. The package only reads the strings.
*/
Client_Request :: struct {
	method:     string,
	upgrade:    string,
	connection: string,
	key:        string,
	version:    string,
	// The raw Sec-WebSocket-Protocol header, if any.
	protocols:  string,
}

/*
validate_client_request checks a server-side opening handshake request
against RFC 6455 section 4.2.1.

Returns `.None` when the server may accept the upgrade. When it returns
`.Unsupported_Version`, answer with status 426 and `Sec-WebSocket-Version: 13`.
Answer every other error with status 400.
*/
validate_client_request :: proc(req: Client_Request) -> Handshake_Error {
	if req.method != "GET" {
		return .Invalid_Method
	}
	if !header_has_token(req.upgrade, "websocket") {
		return .Missing_Upgrade
	}
	if !header_has_token(req.connection, "Upgrade") {
		return .Missing_Connection
	}
	if strings.trim(req.key, " \t") == "" {
		return .Missing_Key
	}
	if !is_valid_key(req.key) {
		return .Invalid_Key
	}
	if strings.trim(req.version, " \t") != VERSION {
		return .Unsupported_Version
	}
	return .None
}

/*
select_subprotocol returns the first entry of `supported` that the client
offered in its Sec-WebSocket-Protocol header, so the server's preference
order wins.

Returns:
- protocol: the chosen entry of `supported`.
- ok: false when nothing matched; the server then omits the header.
*/
select_subprotocol :: proc(offered: string, supported: []string) -> (protocol: string, ok: bool) {
	for s in supported {
		rest := offered
		for part in strings.split_iterator(&rest, ",") {
			if strings.trim(part, " \t") == s {
				return s, true
			}
		}
	}
	return "", false
}

/*
server_response builds the `101 Switching Protocols` response for a request
that passed validate_client_request.

Inputs:
- key: the client's Sec-WebSocket-Key.
- protocol: the chosen subprotocol, or "" to omit the header.
- allocator: allocates the result.

Returns:
- response: the full response head ending in a blank line, owned by the
  caller; free with `delete(response, allocator)`.
- err: an allocator error.
*/
server_response :: proc(key: string, protocol := "", allocator := context.allocator) -> (response: string, err: Error) {
	accept := accept_key(strings.trim(key, " \t"))
	b := strings.builder_make(0, 160, allocator) or_return
	strings.write_string(&b, "HTTP/1.1 101 Switching Protocols\r\n")
	strings.write_string(&b, "Upgrade: websocket\r\n")
	strings.write_string(&b, "Connection: Upgrade\r\n")
	strings.write_string(&b, "Sec-WebSocket-Accept: ")
	strings.write_bytes(&b, accept[:])
	strings.write_string(&b, "\r\n")
	if protocol != "" {
		strings.write_string(&b, "Sec-WebSocket-Protocol: ")
		strings.write_string(&b, protocol)
		strings.write_string(&b, "\r\n")
	}
	strings.write_string(&b, "\r\n")
	return strings.to_string(b), nil
}

/*
client_request builds the opening handshake request a client sends.

Inputs:
- host: the value of the Host header, for example "example.com:8080".
- path: the request target, for example "/chat?room=1".
- key: a Sec-WebSocket-Key from new_key or generate_key.
- protocols: a comma-separated subprotocol list, or "" to omit the header.
- allocator: allocates the result.

Returns:
- request: the full request head ending in a blank line, owned by the
  caller; free with `delete(request, allocator)`.
- err: an allocator error.
*/
client_request :: proc(host, path, key: string, protocols := "", allocator := context.allocator) -> (request: string, err: Error) {
	b := strings.builder_make(0, 192, allocator) or_return
	strings.write_string(&b, "GET ")
	strings.write_string(&b, path == "" ? "/" : path)
	strings.write_string(&b, " HTTP/1.1\r\n")
	strings.write_string(&b, "Host: ")
	strings.write_string(&b, host)
	strings.write_string(&b, "\r\n")
	strings.write_string(&b, "Upgrade: websocket\r\n")
	strings.write_string(&b, "Connection: Upgrade\r\n")
	strings.write_string(&b, "Sec-WebSocket-Key: ")
	strings.write_string(&b, key)
	strings.write_string(&b, "\r\n")
	strings.write_string(&b, "Sec-WebSocket-Version: 13\r\n")
	if protocols != "" {
		strings.write_string(&b, "Sec-WebSocket-Protocol: ")
		strings.write_string(&b, protocols)
		strings.write_string(&b, "\r\n")
	}
	strings.write_string(&b, "\r\n")
	return strings.to_string(b), nil
}

/*
validate_server_response checks the server's answer to a client handshake.

Inputs:
- status: the HTTP status code of the response.
- upgrade, connection, accept: the Upgrade, Connection and
  Sec-WebSocket-Accept header values.
- key: the Sec-WebSocket-Key the client sent.
*/
validate_server_response :: proc(status: int, upgrade, connection, accept, key: string) -> Handshake_Error {
	if status != 101 {
		return .Unexpected_Status
	}
	if !header_has_token(upgrade, "websocket") {
		return .Missing_Upgrade
	}
	if !header_has_token(connection, "Upgrade") {
		return .Missing_Connection
	}
	expected := accept_key(key)
	if strings.trim(accept, " \t") != string(expected[:]) {
		return .Accept_Mismatch
	}
	return .None
}
