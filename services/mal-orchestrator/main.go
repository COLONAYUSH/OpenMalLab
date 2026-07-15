// mal-orchestrator is the durable brain. it runs a temporal worker that owns
// the SubmissionWorkflow and its activities, and (as the pipeline grows) the
// persistence broker that is the only writer of the stores. data-plane workers
// hold no store credentials; the orchestrator brokers every write.
package main

import (
	"log"
	"os"

	"go.temporal.io/sdk/client"
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

func main() {
	c, err := client.Dial(client.Options{
		HostPort:  envOr("TEMPORAL_ADDRESS", "localhost:7233"),
		Namespace: envOr("TEMPORAL_NAMESPACE", "openmallab"),
	})
	if err != nil {
		log.Fatalf("temporal dial: %v", err)
	}
	defer c.Close()

	w := worker.New(c, TaskQueue, worker.Options{})
	w.RegisterWorkflow(SubmissionWorkflow)
	w.RegisterActivity(IdentifyActivity)

	log.Printf("mal-orchestrator worker up (ns=%s queue=%s)", envOr("TEMPORAL_NAMESPACE", "openmallab"), TaskQueue)
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatalf("worker stopped: %v", err)
	}
}
