package callout

import "testing"

// TestConfigModeServerStarts is a harness smoke test: it proves a config-mode server with an
// auth_callout block comes up and that the handler user bypasses the callout (it connects with
// no callout service running at all, which only works because it is in auth_users).
func TestConfigModeServerStarts(t *testing.T) {
	fx := startConfigServer(t)

	nc := fx.connectHandler(t)
	if !nc.IsConnected() {
		t.Fatal("handler should be connected")
	}

	// The client is NOT in auth_users, so with no callout service answering, its connection
	// must fail. If this ever passes, the sentinel wiring is wrong and clients would be
	// authorized without ever consulting the IdP.
	if conn, err := fx.connectClient("mock:u1:u1:role"); err == nil {
		conn.Close()
		t.Fatal("client connected with no callout service running: auth_users wiring is wrong")
	}
}
