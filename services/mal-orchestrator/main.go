// mal-orchestrator is the durable brain. it runs the temporal worker that owns
// the SubmissionWorkflow, and it is the only process that talks to the engine
// socket: every analysis runs as a jailed single-use sibling container it
// spawns, and every result crosses the broker before anything trusted decodes
// it. data-plane workers hold no store credentials; the orchestrator brokers
// everything.
package main

import (
	"context"
	"log"
	"os"
	"time"

	dclient "github.com/docker/docker/client"
	tclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

// TaskQueue is the queue the workflow and activities run on.
const TaskQueue = "openmallab-m0"

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDurOr(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		log.Fatalf("%s: bad duration %q", key, v)
	}
	return def
}

func main() {
	tc, err := tclient.Dial(tclient.Options{
		HostPort:  envOr("TEMPORAL_ADDRESS", "localhost:7233"),
		Namespace: envOr("TEMPORAL_NAMESPACE", "openmallab"),
	})
	if err != nil {
		log.Fatalf("temporal dial: %v", err)
	}
	defer tc.Close()

	docker, err := dclient.NewClientWithOpts(dclient.FromEnv, dclient.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("docker client: %v", err)
	}
	defer docker.Close()

	pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := docker.Ping(pingCtx); err != nil {
		log.Fatalf("docker ping: %v (the orchestrator spawns jailed workers; it needs the engine socket)", err)
	}

	// crash hygiene: jails are single-use; anything labeled and still around
	// from a previous life is garbage.
	if n := reapLeakedJails(pingCtx, docker); n > 0 {
		log.Printf("reaped %d leaked jailed containers", n)
	}

	a := &Analyzer{
		docker:      docker,
		vaultVolume: envOr("MAL_VAULT_VOLUME", "openmallab-vault"),
		workerImage: envOr("MAL_WORKER_IMAGE", "openmallab/mal-static-yara:m0"),
		brokerImage: envOr("MAL_BROKER_IMAGE", "openmallab/mal-broker:m0"),
		workerWall:  envDurOr("MAL_WORKER_WALL_CLOCK", 60*time.Second),
		brokerWall:  envDurOr("MAL_BROKER_WALL_CLOCK", 30*time.Second),
	}

	w := worker.New(tc, TaskQueue, worker.Options{
		// each activity holds a jail (512m, 1 cpu); keep the fleet bounded.
		MaxConcurrentActivityExecutionSize: 4,
	})
	w.RegisterWorkflow(SubmissionWorkflow)
	w.RegisterActivity(a)

	log.Printf("mal-orchestrator worker up (ns=%s queue=%s vault-volume=%s worker=%s broker=%s)",
		envOr("TEMPORAL_NAMESPACE", "openmallab"), TaskQueue, a.vaultVolume, a.workerImage, a.brokerImage)
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatalf("worker stopped: %v", err)
	}
}
