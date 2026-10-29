/*
Example echo_server is a minimal WebSocket echo server on top of `core:net`.
It serves one connection at a time and echoes every message back.

	odin run examples/echo_server
	# then, from a browser console:
	# s = new WebSocket("ws://127.0.0.1:9001"); s.onmessage = e => console.log(e.data); s.send("hi")
*/
package main

import ws "../.."
import "core:fmt"
import "core:net"
import "core:strings"

ADDRESS :: "127.0.0.1:9001"

// read_request reads until the blank line that ends the HTTP request head.
read_request :: proc(sock: net.TCP_Socket, buf: []byte) -> (head: string, rest: []byte, ok: bool) {
	n := 0
	for n < len(buf) {
		got, err := net.recv_tcp(sock, buf[n:])
		if err != nil || got == 0 {
			return
		}
		n += got
		if end := strings.index(string(buf[:n]), "\r\n\r\n"); end >= 0 {
			return string(buf[:end]), buf[end + 4:n], true
		}
	}
	return
}

// parse_request fills a Client_Request from a raw request head.
parse_request :: proc(head: string) -> (req: ws.Client_Request) {
	rest := head
	first := true
	for line in strings.split_lines_iterator(&rest) {
		if first {
			first = false
			req.method, _, _ = strings.partition(line, " ")
			continue
		}
		name, _, value := strings.partition(line, ":")
		value = strings.trim_space(value)
		switch {
		case strings.equal_fold(name, "Upgrade"):
			req.upgrade = value
		case strings.equal_fold(name, "Connection"):
			req.connection = value
		case strings.equal_fold(name, "Sec-WebSocket-Key"):
			req.key = value
		case strings.equal_fold(name, "Sec-WebSocket-Version"):
			req.version = value
		case strings.equal_fold(name, "Sec-WebSocket-Protocol"):
			req.protocols = value
		}
	}
	return
}

// flush writes everything the Conn has queued to the socket.
flush :: proc(sock: net.TCP_Socket, c: ^ws.Conn) -> bool {
	for out := ws.conn_outgoing(c); len(out) > 0; out = ws.conn_outgoing(c) {
		n, err := net.send_tcp(sock, out)
		if err != nil {
			return false
		}
		ws.conn_consume_outgoing(c, n)
	}
	return true
}

serve :: proc(sock: net.TCP_Socket) {
	buf: [8192]byte
	head, rest, ok := read_request(sock, buf[:])
	if !ok {
		return
	}
	req := parse_request(head)
	if err := ws.validate_client_request(req); err != .None {
		fmt.eprintln("rejecting handshake:", err)
		_, _ = net.send_tcp(sock, transmute([]byte)string("HTTP/1.1 400 Bad Request\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	response, rerr := ws.server_response(req.key)
	if rerr != nil {
		return
	}
	defer delete(response)
	if _, err := net.send_tcp(sock, transmute([]byte)response); err != nil {
		return
	}

	c: ws.Conn
	ws.conn_init(&c, .Server)
	defer ws.conn_destroy(&c)
	_ = ws.conn_receive(&c, rest)

	for !ws.conn_should_close(&c) {
		for {
			event, err := ws.conn_next_event(&c)
			if err != nil {
				fmt.eprintln("protocol error:", err)
				break
			}
			if event == nil {
				break
			}
			#partial switch e in event {
			case ws.Message:
				_ = ws.conn_send_message(&c, e.kind, e.data)
			case ws.Close:
				fmt.println("peer closed:", e.code, e.reason)
			}
		}
		if !flush(sock, &c) || ws.conn_should_close(&c) {
			break
		}
		n, err := net.recv_tcp(sock, buf[:])
		if err != nil || n == 0 {
			break
		}
		_ = ws.conn_receive(&c, buf[:n])
	}
}

main :: proc() {
	endpoint, ok := net.parse_endpoint(ADDRESS)
	if !ok {
		fmt.eprintln("bad address", ADDRESS)
		return
	}
	listener, err := net.listen_tcp(endpoint)
	if err != nil {
		fmt.eprintln("listen failed:", err)
		return
	}
	defer net.close(listener)
	fmt.println("echo server listening on ws://" + ADDRESS)

	for {
		client, _, aerr := net.accept_tcp(listener)
		if aerr != nil {
			fmt.eprintln("accept failed:", aerr)
			continue
		}
		serve(client)
		net.close(client)
	}
}
