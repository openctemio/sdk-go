package sensorkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// EnvJobID is the environment variable a sensor built on the kit reads to
// run the one platform command with this id and exit (RunJob) instead of
// polling for work.
const EnvJobID = "SENSOR_JOB_ID"

// JobDeliveryTimeout bounds how long a job run waits for the outbox to
// deliver its results before it exits.
var JobDeliveryTimeout = 5 * time.Minute

// RunJob runs the one platform command with id and returns: the sensor as
// a Kubernetes Job (or any one-shot launcher) that the platform, an
// autoscaler or an operator starts per job. It sets up everything Run sets
// up (identity, manifest, tools, local policy, outbox, heartbeats, which
// keep the command's lease and carry cancels), then claims the command by
// id and runs it through the same checks and executor as a polled command:
// the local kill switch, the command types this sensor serves, the expiry,
// the local policy, the platform's tool gate. It waits for the outbox to
// deliver the results (JobDeliveryTimeout) and stops.
//
// It returns nil when the command ran and its results were delivered,
// whatever the command's own outcome (a failed scan is reported to the
// platform as failed: retrying the Job would not change it). It returns an
// error when the command could not be claimed (another sensor holds it, it
// is not pending, it is another tenant's: the platform refuses), was not
// run (released back to the platform), or its results are still in the
// outbox when the wait ends. Mount the outbox on a persistent volume for a
// Job, or results left undelivered are lost with the pod.
//
// A stop signal stops the command and releases it to the platform, as a
// drain does.
func (k *Kit) RunJob(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("sensorkit: RunJob needs a command id")
	}
	if k.client == nil || !k.s.commands {
		return errors.New("sensorkit: a job runs only with a platform connection and commands on")
	}
	k.jobID = id
	return k.Run(ctx)
}

// runOneJob is Run's job mode, after the first accepted heartbeat: start
// the heartbeat loop, run the job, wait for delivery, stop.
func (k *Kit) runOneJob(ctx context.Context, poller *core.CommandPoller) error {
	s, out, errw := k.sensor, k.out, k.errw
	if poller == nil {
		return errors.New("sensorkit: a job runs only with a platform connection and commands on")
	}
	if err := s.Start(ctx); err != nil {
		return fmt.Errorf("failed to start sensor: %w", err)
	}
	_, _ = fmt.Fprintf(out, "\n%s: running job %s, then exiting\n", k.s.name, k.jobID)
	jobErr := k.runClaimedJob(ctx, poller)
	deliverErr := k.awaitJobDelivery(ctx)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Stop(shutdownCtx); err != nil {
		_, _ = fmt.Fprintf(errw, "Shutdown error: %v\n", err)
	}
	if err := errors.Join(jobErr, deliverErr); err != nil {
		_, _ = fmt.Fprintf(errw, "Job %s: %v\n", k.jobID, err)
		return err
	}
	_, _ = fmt.Fprintf(out, "Job %s done.\n", k.jobID)
	return nil
}

func (k *Kit) runClaimedJob(ctx context.Context, poller *core.CommandPoller) error {
	cmd, err := k.client.ClaimCommand(ctx, k.jobID)
	if err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	return poller.RunClaimed(ctx, cmd)
}

// awaitJobDelivery waits until the outbox holds nothing for delivery (at
// most JobDeliveryTimeout, or 20 seconds after a stop signal).
func (k *Kit) awaitJobDelivery(ctx context.Context) error {
	ob := k.client.Outbox()
	if ob == nil {
		return nil
	}
	wait := JobDeliveryTimeout
	if ctx.Err() != nil {
		wait = min(wait, 20*time.Second)
	}
	deadline := time.Now().Add(wait)
	for {
		st := ob.Stats()
		if st.PendingCount == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d result(s) not delivered within %s; they stay in the outbox (%s)", st.PendingCount, wait, ob.Dir())
		}
		time.Sleep(250 * time.Millisecond)
	}
}
