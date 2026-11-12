package client

import (
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
)

// responseHeadBytes is how much of an oversized answer ResponseTooLargeError
// keeps. A command's id is among the first bytes of its JSON object; the
// sensor reads it to fail that one command.
const responseHeadBytes = 4 << 10

// ResponseTooLargeError is returned when the platform's answer is larger than
// the client reads (Limit bytes). errors.Is(err, core.ErrResponseTooLarge)
// matches it. The request is not retried.
type ResponseTooLargeError struct {
	// Limit is the largest answer the client reads, in bytes.
	Limit int
	// Head is a copy of the first bytes of the answer (at most 4 KiB). It is
	// a fragment of untrusted, truncated data: never run anything from it.
	Head []byte
}

func (e *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("response body exceeds %d bytes", e.Limit)
}

// Unwrap makes errors.Is(err, core.ErrResponseTooLarge) true.
func (e *ResponseTooLargeError) Unwrap() error { return core.ErrResponseTooLarge }

// ResponseHead implements core.ResponseHeadProvider.
func (e *ResponseTooLargeError) ResponseHead() []byte { return e.Head }

// newResponseTooLarge builds the error from the bytes read so far (more than
// the limit): it keeps a copy of the first responseHeadBytes.
func newResponseTooLarge(data []byte) *ResponseTooLargeError {
	return &ResponseTooLargeError{Limit: maxResponseBodyBytes, Head: append([]byte(nil), data[:min(len(data), responseHeadBytes)]...)}
}
