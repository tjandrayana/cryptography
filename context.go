package cryptography

import (
	"context"
	"time"
)

// WithTimeout creates a context with a timeout.
// This is a convenience wrapper around context.WithTimeout.
func WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// WithDeadline creates a context with a deadline.
// This is a convenience wrapper around context.WithDeadline.
func WithDeadline(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(parent, deadline)
}

// WithCancel creates a context that can be cancelled.
// This is a convenience wrapper around context.WithCancel.
func WithCancel(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}
