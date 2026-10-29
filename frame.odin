package websocket

// MAX_HEADER_SIZE is the largest possible frame header: 2 + 8 length bytes + 4 mask bytes.
MAX_HEADER_SIZE :: 14

// MAX_CONTROL_PAYLOAD is the largest payload a close, ping or pong frame may carry.
MAX_CONTROL_PAYLOAD :: 125

/*
Frame_Header holds the fields of a frame header from RFC 6455 section 5.2.

The payload itself isn't part of the header. When `masked` is true, the
payload on the wire is XORed with `mask_key`; apply_mask undoes that.
*/
Frame_Header :: struct {
	// Set on the last frame of a message.
	fin:         bool,
	// Extension bits; must be false unless an extension defines them.
	rsv1:        bool,
	rsv2:        bool,
	rsv3:        bool,
	opcode:      Opcode,
	// Set when the payload is masked. Clients mask every frame they send.
	masked:      bool,
	mask_key:    [4]byte,
	// Length of the payload in bytes.
	payload_len: u64,
}

/*
header_size returns how many bytes encode_header writes for a header with
the given payload length and masking.
*/
header_size :: proc "contextless" (payload_len: u64, masked: bool) -> int {
	n := 2
	switch {
	case payload_len > 0xFFFF:
		n += 8
	case payload_len > 125:
		n += 2
	}
	if masked {
		n += 4
	}
	return n
}

/*
decode_header reads one frame header from the start of `data`.

It validates everything that the header alone can tell: reserved bits,
reserved opcodes, control frame rules and length encoding. It doesn't check
masking direction, because that depends on the role; Conn does that.

Inputs:
- data: bytes received so far, starting at a frame boundary.
- allow_rsv: set to accept RSV bits, for example when an extension is in use.

Returns:
- header: the decoded header.
- size: how many bytes of `data` the header used; the payload starts there.
- err: `.Incomplete` when `data` is too short, or another `Frame_Error`.
*/
decode_header :: proc "contextless" (data: []byte, allow_rsv := false) -> (header: Frame_Header, size: int, err: Frame_Error) {
	if len(data) < 2 {
		return {}, 0, .Incomplete
	}
	b0, b1 := data[0], data[1]
	header.fin = b0 & 0x80 != 0
	header.rsv1 = b0 & 0x40 != 0
	header.rsv2 = b0 & 0x20 != 0
	header.rsv3 = b0 & 0x10 != 0
	header.masked = b1 & 0x80 != 0

	raw_op := b0 & 0x0F
	switch raw_op {
	case 0x0, 0x1, 0x2, 0x8, 0x9, 0xA:
		header.opcode = Opcode(raw_op)
	case:
		return {}, 0, .Reserved_Opcode
	}
	if !allow_rsv && (header.rsv1 || header.rsv2 || header.rsv3) {
		return {}, 0, .Reserved_Bits_Set
	}

	length := u64(b1 & 0x7F)
	if opcode_is_control(header.opcode) {
		if !header.fin {
			return {}, 0, .Fragmented_Control_Frame
		}
		if length > MAX_CONTROL_PAYLOAD {
			return {}, 0, .Control_Frame_Too_Long
		}
	}

	pos := 2
	switch length {
	case 126:
		if len(data) < pos + 2 {
			return {}, 0, .Incomplete
		}
		length = u64(data[2]) << 8 | u64(data[3])
		pos += 2
		if length < 126 {
			return {}, 0, .Non_Minimal_Length
		}
	case 127:
		if len(data) < pos + 8 {
			return {}, 0, .Incomplete
		}
		length = 0
		for i in 0 ..< 8 {
			length = length << 8 | u64(data[2 + i])
		}
		pos += 8
		if length >> 63 != 0 {
			return {}, 0, .Payload_Length_Overflow
		}
		if length <= 0xFFFF {
			return {}, 0, .Non_Minimal_Length
		}
	}
	header.payload_len = length

	if header.masked {
		if len(data) < pos + 4 {
			return {}, 0, .Incomplete
		}
		copy(header.mask_key[:], data[pos:pos + 4])
		pos += 4
	}
	return header, pos, .None
}

/*
encode_header writes `header` to the start of `buf` using the shortest
length encoding.

Returns:
- n: the number of bytes written, equal to header_size.
- err: `.Buffer_Too_Small` when `buf` can't hold the header, or a
  `Frame_Error` when the header breaks a control frame rule.
*/
encode_header :: proc "contextless" (buf: []byte, header: Frame_Header) -> (n: int, err: Frame_Error) {
	if opcode_is_control(header.opcode) {
		if !header.fin {
			return 0, .Fragmented_Control_Frame
		}
		if header.payload_len > MAX_CONTROL_PAYLOAD {
			return 0, .Control_Frame_Too_Long
		}
	}
	if header.payload_len >> 63 != 0 {
		return 0, .Payload_Length_Overflow
	}
	n = header_size(header.payload_len, header.masked)
	if len(buf) < n {
		return 0, .Buffer_Too_Small
	}

	b0 := u8(header.opcode)
	if header.fin {
		b0 |= 0x80
	}
	if header.rsv1 {
		b0 |= 0x40
	}
	if header.rsv2 {
		b0 |= 0x20
	}
	if header.rsv3 {
		b0 |= 0x10
	}
	buf[0] = b0
	mask_bit: u8 = header.masked ? 0x80 : 0

	pos := 2
	switch {
	case header.payload_len > 0xFFFF:
		buf[1] = mask_bit | 127
		for i in 0 ..< 8 {
			buf[2 + i] = u8(header.payload_len >> (56 - 8 * uint(i)))
		}
		pos += 8
	case header.payload_len > 125:
		buf[1] = mask_bit | 126
		buf[2] = u8(header.payload_len >> 8)
		buf[3] = u8(header.payload_len)
		pos += 2
	case:
		buf[1] = mask_bit | u8(header.payload_len)
	}
	if header.masked {
		for i in 0 ..< 4 {
			buf[pos + i] = header.mask_key[i]
		}
	}
	return n, .None
}

/*
apply_mask XORs `data` in place with `key`. Applying it twice restores the
original bytes, so the same call masks and unmasks.

Inputs:
- data: the payload bytes to transform.
- key: the 4-byte masking key from the frame header.
- offset: the position of `data[0]` within the whole payload, which lets you
  unmask a payload that arrives in several chunks.
*/
apply_mask :: proc "contextless" (data: []byte, key: [4]byte, offset := 0) {
	o := offset & 3
	for i in 0 ..< len(data) {
		data[i] ~= key[(o + i) & 3]
	}
}

/*
encode_frame_into writes a complete frame, header and payload, to `buf`.
When `header.masked` is true it masks the copied payload; `payload` itself
is never modified. The header's `payload_len` is set from `payload`.

Returns:
- n: the number of bytes written.
- err: `.Buffer_Too_Small` or another `Frame_Error`.
*/
encode_frame_into :: proc "contextless" (buf: []byte, header: Frame_Header, payload: []byte) -> (n: int, err: Frame_Error) {
	h := header
	h.payload_len = u64(len(payload))
	size := encode_header(buf, h) or_return
	if len(buf) - size < len(payload) {
		return 0, .Buffer_Too_Small
	}
	copy(buf[size:], payload)
	if h.masked {
		apply_mask(buf[size:size + len(payload)], h.mask_key)
	}
	return size + len(payload), .None
}

/*
encode_frame returns a newly allocated frame holding `header` and `payload`.

Returns:
- frame: the encoded bytes, owned by the caller; free with `delete(frame, allocator)`.
- err: a `Frame_Error` or an allocator error.
*/
encode_frame :: proc(header: Frame_Header, payload: []byte, allocator := context.allocator) -> (frame: []byte, err: Error) {
	size := header_size(u64(len(payload)), header.masked) + len(payload)
	frame = make([]byte, size, allocator) or_return
	if _, ferr := encode_frame_into(frame, header, payload); ferr != .None {
		delete(frame, allocator)
		return nil, ferr
	}
	return frame, nil
}

@(private)
append_frame :: proc(out: ^[dynamic]byte, header: Frame_Header, payload: []byte) -> Error {
	h := header
	h.payload_len = u64(len(payload))
	start := len(out)
	size := header_size(h.payload_len, h.masked) + len(payload)
	resize(out, start + size) or_return
	if _, ferr := encode_frame_into(out[start:], h, payload); ferr != .None {
		_ = resize(out, start)
		return ferr
	}
	return nil
}
