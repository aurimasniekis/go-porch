package app

import (
	"context"
	"time"

	"github.com/aurimasniekis/go-pulse/pkg/pulse"

	"github.com/aurimasniekis/go-porch/internal/events"
)

// relayLoop connects to pulse (retrying while it is unreachable) and relays outbox events until ctx ends. Pulse
// being down never affects requests: events wait in the outbox.
func (a *App) relayLoop(ctx context.Context) {
	pc := a.Cfg.Events.Pulse
	if !pc.Enabled {
		return
	}
	opts := []pulse.Option{pulse.WithCredsFile(pc.CredsFile), pulse.WithSource(pc.Source), pulse.WithName("porch")}
	if pc.CAFile != "" {
		opts = append(opts, pulse.WithCAFile(pc.CAFile))
	}
	for {
		c, err := pulse.Connect(pc.URL, opts...)
		if err == nil {
			a.Log.Info("event relay connected to pulse", "url", pc.URL)
			r := &events.Relay{Store: a.Store, Pub: c, Clock: a.Clock, Metrics: a.Metrics, Log: a.Log}
			r.Run(ctx, 2*time.Second)
			c.Close()
			return
		}
		a.Log.Warn("event relay: cannot connect to pulse; events wait in the outbox", "url", pc.URL, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}
