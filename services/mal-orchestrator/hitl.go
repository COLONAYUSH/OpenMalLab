package main

// human-in-the-loop via Temporal signals (design sec 07). when the confidence
// gate escalates, AgentGraphWorkflow raises a typed review task, exposes it to the
// console through a workflow QUERY, and durably AWAITs the analyst's decision
// SIGNAL (or a long timeout, after which the deterministic verdict simply stands -
// the workflow never holds a process while it waits). the analyst's decision is a
// gold label: on approval the analysis facts are curated into the knowledge graph,
// the same action that unblocks this run trains the next.

import "time"

const (
	// the console sends the decision via this signal; it reads the pending task via
	// this query. the workflow waits at most reviewTimeout for a human.
	reviewSignalName = "review-decision"
	reviewQueryName  = "pending-review"
	reviewTimeout    = 7 * 24 * time.Hour
)

// ReviewRequest is the HITL task the console reads (workflow query) when the gate
// escalates: what to look at, and the escalated categories + reasons.
type ReviewRequest struct {
	SubmissionID string   `json:"submission_id"`
	Question     string   `json:"question"`
	Kinds        []string `json:"kinds"`
	Reasons      []string `json:"reasons"`
}

// ReviewDecision is the analyst's answer, delivered by signal. Approved confirms
// the AI's escalated findings and promotes the analysis facts to curated; Note is
// an optional free-text annotation.
type ReviewDecision struct {
	Approved bool   `json:"approved"`
	Note     string `json:"note"`
}
