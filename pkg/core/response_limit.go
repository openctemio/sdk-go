package core

import "errors"

// ErrResponseTooLarge is what an API client's error wraps (errors.Is) when
// the platform's answer is larger than the client reads (10 MiB). The answer
// is not retried: the platform would send the same bytes again. The
// CommandPoller reacts to it on the commands poll: it asks for fewer commands
// and, when even one is too large, fails that one command by its id.
var ErrResponseTooLarge = errors.New("the platform's answer is larger than the sensor reads")

// ResponseHeadProvider is implemented by an error that wraps
// ErrResponseTooLarge and keeps the first bytes of the answer. The poller
// reads the id of the first command from them; it never acts on anything
// else in a truncated answer.
type ResponseHeadProvider interface {
	ResponseHead() []byte
}
