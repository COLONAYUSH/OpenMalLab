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
	"strconv"
	"time"

	dclient "github.com/docker/docker/client"
	tclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/COLONAYUSH/OpenMalLab/internal/aiplane"
	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
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

func envInt64Or(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
		log.Fatalf("%s: bad integer %q", key, v)
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

	a := &Analyzer{
		docker:        docker,
		vaultVolume:   envOr("MAL_VAULT_VOLUME", "openmallab-vault"),
		vaultPath:     envOr("MAL_VAULT_DIR", "/vault"),
		stagingPath:   envOr("MAL_EXTRACT_STAGING_DIR", "/staging"),
		stagingVol:    envOr("MAL_EXTRACT_STAGING_VOLUME", "openmallab-extract-staging"),
		workerImage:   envOr("MAL_WORKER_IMAGE", "openmallab/mal-static-yara:m0"),
		identImage:    envOr("MAL_IDENT_IMAGE", "openmallab/mal-ident:m0"),
		extractImage:  envOr("MAL_EXTRACT_IMAGE", "openmallab/mal-extract:m0"),
		capaImage:     envOr("MAL_CAPA_IMAGE", "openmallab/mal-capa:m0"),
		flossImage:    envOr("MAL_FLOSS_IMAGE", "openmallab/mal-floss:m0"),
		brokerImage:   envOr("MAL_BROKER_IMAGE", "openmallab/mal-broker:m0"),
		workerWall:    envDurOr("MAL_WORKER_WALL_CLOCK", 60*time.Second),
		identWall:     envDurOr("MAL_IDENT_WALL_CLOCK", 30*time.Second),
		extractWall:   envDurOr("MAL_EXTRACT_WALL_CLOCK", 60*time.Second),
		capaWall:      envDurOr("MAL_CAPA_WALL_CLOCK", 300*time.Second),
		flossWall:     envDurOr("MAL_FLOSS_WALL_CLOCK", 360*time.Second), // static + emulation phases
		brokerWall:    envDurOr("MAL_BROKER_WALL_CLOCK", 30*time.Second),
		capaMemBytes:  envInt64Or("MAL_CAPA_MEMORY_BYTES", 2<<30), // 2 GiB; vivisect is hungry
		capaScratch:   envOr("MAL_CAPA_SCRATCH", "256m"),
		flossMemBytes: envInt64Or("MAL_FLOSS_MEMORY_BYTES", 2<<30),
		flossScratch:  envOr("MAL_FLOSS_SCRATCH", "256m"),
	}

	// crash hygiene: jails are single-use and staging dirs are per-run; anything
	// left from a previous life is garbage.
	if n := reapLeakedJails(pingCtx, docker); n > 0 {
		log.Printf("reaped %d leaked jailed containers", n)
	}
	if n := a.sweepStaging(); n > 0 {
		log.Printf("swept %d leftover staging dirs", n)
	}
	if n := a.sweepVaultTemps(); n > 0 {
		log.Printf("swept %d leftover vault temp files", n)
	}

	// optional AI-analyst plane (air-gapped by default). only wired when a local
	// model URL is configured; even then enrichment is async and caged, run by the
	// separate EnrichmentWorkflow that never touches the deterministic verdict.
	if url := os.Getenv("MAL_MODEL_URL"); url != "" {
		prov, err := aiplane.NewLocalProvider(url, envOr("MAL_MODEL_NAME", "local"))
		if err != nil {
			log.Fatalf("MAL_MODEL_URL: %v", err)
		}
		// unseeded L0: until the curated corpora are loaded no citation grounds, so
		// every hypothesis escalates or drops - safe (no false autonomy).
		reg := knowledge.NewRegistry(knowledge.NewMemStore())
		a.aiplane = aiplane.NewAIPlane(prov, aiplane.NewGate(reg))
		log.Printf("AI-analyst plane enabled (model=%s); enrichment is async and caged", url)
	}

	// optional multi-agent graph (design sec 05). air-gapped by default: nil unless
	// a roster service URL is configured. seeds L0 so cited facts can ground on day
	// one; caged and async like the single-analyst path (see AgentGraphWorkflow).
	if au := os.Getenv("MAL_AGENTS_URL"); au != "" {
		reg := knowledge.NewRegistry(knowledge.NewMemStore())
		n, _, err := reg.SeedStarter()
		if err != nil {
			log.Fatalf("seed L0: %v", err)
		}
		a.agents = newHTTPAgentCaller(au)
		a.registry = reg // spine-side retrieval + citation source of truth
		a.agentLedger = aiplane.NewLedger()
		a.graph = knowledge.NewGraph(knowledge.NewMemGraph()) // tier-1 learning target (in-memory until a persistent store lands, ASK STORE-1)
		a.grad = aiplane.NewGraduation()                      // fed by HITL outcomes (sec 14); built BEFORE the gate so it can govern autonomy
		a.calibration = aiplane.NewCalibration()              // downgrades mis-calibrated confidence (sec 06/11)
		// the gate consults graduation: a category auto-accepts only once it has EARNED
		// autonomy through the HITL loop. until then a grounded accept escalates instead,
		// so the track record actually gates autonomy (never a day-one auto-accept).
		a.gate = aiplane.NewGateWithGraduation(reg, a.grad)
		log.Printf("AI agent-graph enabled (roster=%s, L0 seeded with %d facts); enrichment is async and caged", au, n)
	}

	w := worker.New(tc, TaskQueue, worker.Options{
		// each activity holds a jail (512m, 1 cpu); keep the fleet bounded.
		MaxConcurrentActivityExecutionSize: 4,
	})
	w.RegisterWorkflow(SubmissionWorkflow)
	w.RegisterWorkflow(EnrichmentWorkflow)
	w.RegisterWorkflow(AgentGraphWorkflow)
	w.RegisterActivity(a)

	log.Printf("mal-orchestrator worker up (ns=%s queue=%s vault=%s yara=%s ident=%s extract=%s capa=%s floss=%s broker=%s)",
		envOr("TEMPORAL_NAMESPACE", "openmallab"), TaskQueue, a.vaultVolume, a.workerImage, a.identImage, a.extractImage, a.capaImage, a.flossImage, a.brokerImage)
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatalf("worker stopped: %v", err)
	}
}
