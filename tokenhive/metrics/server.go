package metrics

import (
	"encoding/json"
	"net/http"
	"time"
)

// Server is the pull half of the instrumentation: it serves what the store
// retained.
//
//	GET /timing    every retained record, oldest first
//
// One JSON object per pull, so a pull is self-describing:
//
//	service     which process answered
//	retained    records the ring holds right now
//	served      records in this answer, which is all of them
//	total       requests recorded since the process started
//	dropped     records evicted to make room, cumulatively
//	records     the records themselves, oldest first, each with its sequence
//	aggregate   the last summary the TEE emitted, when it has emitted one
//
// dropped and retained are the two numbers that say whether a pull is complete:
// a puller that sees dropped climb, or retained at the ring's size, knows the
// store has rolled past what it wanted and should poll more often. Nothing else
// here can say that — a ring that has forgotten something looks exactly like a
// quiet TEE.
type Server struct {
	Store *Store
}

// NewHTTPServer returns a server for the given store and registers its route on
// mux. A nil mux means a fresh one, which the caller then owns.
func NewHTTPServer(store *Store, mux *http.ServeMux) *Server {
	if mux == nil {
		mux = http.NewServeMux()
	}
	s := &Server{Store: store}
	mux.HandleFunc("/timing", s.handleTiming)
	return s
}

// timingResponse is the wire shape of one pull. Each record is the flattened
// record (see tee.TimingRecord.Flat) plus the two fields only a stored record
// has: the sequence it was stored under and when it was reported.
type timingResponse struct {
	Service   string           `json:"service"`
	Retained  int              `json:"retained"`
	Served    int              `json:"served"`
	Total     uint64           `json:"total"`
	Dropped   uint64           `json:"dropped"`
	Records   []map[string]any `json:"records"`
	Aggregate map[string]any   `json:"aggregate,omitempty"`
}

func (s *Server) handleTiming(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snap := s.Store.snapshot()
	out := timingResponse{
		Service:  snap.service,
		Retained: snap.retained,
		Served:   len(snap.entries),
		Total:    snap.total,
		Dropped:  snap.dropped,
		Records:  make([]map[string]any, 0, len(snap.entries)),
	}
	for _, e := range snap.entries {
		fields := make(map[string]any, len(e.rec.Flat())+2)
		for _, f := range e.rec.Flat() {
			fields[f.Name] = f.Value
		}
		fields["seq"] = e.seq
		fields["at"] = e.rec.At.UTC().Format(time.RFC3339Nano)
		out.Records = append(out.Records, fields)
	}
	if agg := snap.aggregate; agg != nil {
		fields := make(map[string]any, len(agg.Flat()))
		for _, f := range agg.Flat() {
			fields[f.Name] = f.Value
		}
		out.Aggregate = fields
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	// A response that cannot be written is the caller's to notice: there is
	// nowhere left to report it from here.
	_ = json.NewEncoder(w).Encode(out)
}
