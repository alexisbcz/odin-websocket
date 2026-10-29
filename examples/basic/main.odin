// Example basic wires a client Conn to a server Conn in memory. Run it with `odin run examples/basic`.
package main

import ws "../.."
import "core:fmt"
import "core:os"

// pump moves every queued byte from one connection to the other, as a socket would.
pump :: proc(from, to: ^ws.Conn) {
	out := ws.conn_outgoing(from)
	_ = ws.conn_receive(to, out)
	ws.conn_consume_outgoing(from, len(out))
}

// drain prints every event the connection has ready.
drain :: proc(name: string, c: ^ws.Conn) -> bool {
	for {
		event, err := ws.conn_next_event(c)
		if err != nil {
			fmt.eprintln(name, "protocol error:", err)
			return false
		}
		switch e in event {
		case nil:
			return true
		case ws.Message:
			fmt.printfln("%s got %v message: %q", name, e.kind, ws.message_text(e))
		case ws.Ping:
			fmt.printfln("%s got ping %q and queued a pong", name, string(e.payload))
		case ws.Pong:
			fmt.printfln("%s got pong %q", name, string(e.payload))
		case ws.Close:
			fmt.printfln("%s got close %v %q", name, e.code, e.reason)
		}
	}
}

main :: proc() {
	// 1. Opening handshake: the client sends a key, the server proves it read it.
	key, ok := ws.new_key()
	if !ok {
		fmt.eprintln("no entropy source")
		os.exit(1)
	}
	request, rerr := ws.client_request("localhost:9001", "/chat", string(key[:]))
	if rerr != nil {
		os.exit(1)
	}
	defer delete(request)
	fmt.print(request)

	check := ws.validate_client_request({
		method = "GET",
		upgrade = "websocket",
		connection = "Upgrade",
		key = string(key[:]),
		version = "13",
	})
	accept := ws.accept_key(string(key[:]))
	fmt.println("server check:", check, "accept:", string(accept[:]))
	fmt.println("client check:", ws.validate_server_response(101, "websocket", "Upgrade", string(accept[:]), string(key[:])))

	// 2. Frames: both sides speak through Conn state machines.
	client, server: ws.Conn
	ws.conn_init(&client, .Client, {fragment_size = 8})
	defer ws.conn_destroy(&client)
	ws.conn_init(&server, .Server)
	defer ws.conn_destroy(&server)

	_ = ws.conn_send_text(&client, "Hello from a fragmented message")
	_ = ws.conn_send_ping(&client, transmute([]byte)string("are you there?"))
	pump(&client, &server)
	if !drain("server", &server) {
		os.exit(1)
	}

	_ = ws.conn_send_text(&server, "Hi, client")
	pump(&server, &client)
	_ = drain("client", &client)

	// 3. Closing handshake: the client starts it and the server echoes it.
	_ = ws.conn_close(&client, .Normal, "bye")
	pump(&client, &server)
	_ = drain("server", &server)
	pump(&server, &client)
	_ = drain("client", &client)
	fmt.println("client may close transport:", ws.conn_should_close(&client))
	fmt.println("server may close transport:", ws.conn_should_close(&server))
}
