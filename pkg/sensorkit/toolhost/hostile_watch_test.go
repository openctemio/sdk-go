package toolhost

import (
	"os"
	"time"
)

// hangAfterSettling settles every target (settle-all-then-hang) or only the
// first (settle-one-then-heartbeat) and then sends nothing but heartbeats,
// using no CPU: a tool hung after its work (the incident 2026-10-25), or
// one stuck mid-run. The first ignores a cancel (it must be killed); the
// second honors it.
func hangAfterSettling(mode string, send func(string), read func() map[string]any) {
	send(`{"v":1,"type":"record","kind":"finding","target":"t1","data":{"type":"misconfiguration","title":"on t1","severity":"low"}}`)
	send(`{"v":1,"type":"target_status","target":"t1","status":"done"}`)
	if mode == "settle-all-then-hang" {
		send(`{"v":1,"type":"target_status","target":"t2","status":"done"}`)
	} else {
		go func() {
			for {
				if m := read(); m["type"] == "cancel" {
					send(`{"v":1,"type":"result","status":"canceled"}`)
					os.Exit(0)
				}
			}
		}()
	}
	for {
		send(`{"v":1,"type":"heartbeat"}`)
		time.Sleep(200 * time.Millisecond)
	}
}
