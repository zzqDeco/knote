package protocol

import "time"

type EventType string

const (
	EventGatewayReady    EventType = "gateway.ready"
	EventSessionInfo     EventType = "session.info"
	EventUserMessage     EventType = "message.user"
	EventAssistantStart  EventType = "message.start"
	EventAssistantDelta  EventType = "message.delta"
	EventAssistantDone   EventType = "message.complete"
	EventToolStart       EventType = "tool.start"
	EventToolProgress    EventType = "tool.progress"
	EventToolComplete    EventType = "tool.complete"
	EventToolError       EventType = "tool.error"
	EventBuildStart      EventType = "build.start"
	EventBuildProgress   EventType = "build.progress"
	EventBuildComplete   EventType = "build.complete"
	EventVersionChanged  EventType = "version.changed"
	EventVersionDiff     EventType = "version.diff"
	EventApprovalRequest EventType = "approval.request"
	EventConfirmRequest  EventType = "confirm.request"
	EventTaskStarted     EventType = "task.started"
	EventTaskProgress    EventType = "task.progress"
	EventTaskComplete    EventType = "task.complete"
	EventStatusUpdate    EventType = "status.update"
	EventUsageUpdate     EventType = "usage.update"
	EventError           EventType = "error"
)

type Event struct {
	Type      EventType `json:"type"`
	SessionID string    `json:"session_id,omitempty"`
	Message   string    `json:"message,omitempty"`
	Payload   any       `json:"payload,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func NewEvent(eventType EventType, sessionID, message string, payload any) Event {
	return Event{
		Type:      eventType,
		SessionID: sessionID,
		Message:   message,
		Payload:   payload,
		CreatedAt: time.Now().UTC(),
	}
}

type SessionInfo struct {
	ID        string    `json:"id"`
	Workspace string    `json:"workspace"`
	Branch    string    `json:"branch,omitempty"`
	Dirty     bool      `json:"dirty"`
	CreatedAt time.Time `json:"created_at"`
	Resumed   bool      `json:"resumed"`
}

type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskKilled    TaskStatus = "killed"
)

type Task struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Status      TaskStatus `json:"status"`
	Owner       string     `json:"owner,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Message     string     `json:"message,omitempty"`
}

type PermissionOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Scope string `json:"scope"`
}

type PermissionRequest struct {
	RequestID string             `json:"request_id"`
	Tool      string             `json:"tool"`
	Title     string             `json:"title"`
	Question  string             `json:"question"`
	Summary   string             `json:"summary"`
	Options   []PermissionOption `json:"options"`
	CreatedAt time.Time          `json:"created_at"`
}

type ArtifactManifest struct {
	Version       int       `json:"version"`
	Workspace     string    `json:"workspace"`
	GeneratedAt   time.Time `json:"generated_at"`
	SourceCount   int       `json:"source_count"`
	DocumentCount int       `json:"document_count"`
	ChunkCount    int       `json:"chunk_count"`
	EntityCount   int       `json:"entity_count"`
	RelationCount int       `json:"relation_count"`
	ClaimCount    int       `json:"claim_count"`
	SummaryCount  int       `json:"summary_count"`
}

type Document struct {
	DocumentID  string    `json:"document_id"`
	Path        string    `json:"path"`
	ContentHash string    `json:"content_hash"`
	Title       string    `json:"title,omitempty"`
	Mtime       time.Time `json:"mtime"`
}

type Chunk struct {
	ChunkID    string `json:"chunk_id"`
	DocumentID string `json:"document_id"`
	Span       [2]int `json:"span"`
	Text       string `json:"text"`
	Hash       string `json:"hash"`
}

type Entity struct {
	EntityID         string   `json:"entity_id"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Aliases          []string `json:"aliases"`
	EvidenceChunkIDs []string `json:"evidence_chunk_ids"`
}

type Relation struct {
	RelationID       string   `json:"relation_id"`
	SubjectID        string   `json:"subject_id"`
	Predicate        string   `json:"predicate"`
	ObjectID         string   `json:"object_id"`
	EvidenceChunkIDs []string `json:"evidence_chunk_ids"`
}

type Claim struct {
	ClaimID          string   `json:"claim_id"`
	Text             string   `json:"text"`
	Confidence       string   `json:"confidence"`
	EvidenceChunkIDs []string `json:"evidence_chunk_ids"`
}

type Summary struct {
	SummaryID        string   `json:"summary_id"`
	Text             string   `json:"text"`
	EvidenceChunkIDs []string `json:"evidence_chunk_ids"`
}

type BuildResult struct {
	Manifest protocolManifestAlias `json:"manifest"`
	Report   string                `json:"report"`
}

type protocolManifestAlias = ArtifactManifest

type QueryResult struct {
	Answer      string   `json:"answer"`
	Evidence    []string `json:"evidence"`
	Uncertainty string   `json:"uncertainty,omitempty"`
}
