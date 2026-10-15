package client

import "github.com/openctemio/sdk-go/pkg/core"

// jobLedgerHolder lets SetJobLedger swap the ledger while results flow.
type jobLedgerHolder struct{ l *core.JobLedger }

// SetJobLedger makes the client refuse, before anything is stored or sent,
// a result for a command the ledger does not hold (a shared sensor, api
// RFC-100 §8): a report needs a held command with a known organization and
// is tagged with it in the outbox; a command result or a log batch needs a
// held command. nil turns the check off.
func (c *Client) SetJobLedger(l *core.JobLedger) {
	if l == nil {
		c.ledger.Store(nil)
		return
	}
	c.ledger.Store(&jobLedgerHolder{l: l})
}

// jobLedger is the ledger in force (nil: none).
func (c *Client) jobLedger() *core.JobLedger {
	if h := c.ledger.Load(); h != nil {
		return h.l
	}
	return nil
}
