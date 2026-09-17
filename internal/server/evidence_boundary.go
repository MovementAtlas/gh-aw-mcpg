package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"unicode/utf8"
)

// evidenceBoundary is shared by every routed/unified handler in one gateway.
// The lease is deliberately not resumable: a restarted owner refuses evidence.
// It is provisioned outside agent mounts, separately from the reader's lease.
type evidenceBoundary struct {
	mu     sync.Mutex
	path   string
	owner  *os.File
	failed bool
	state  evidenceBudget
}

type evidenceBudget struct {
	IndexUsed      bool `json:"indexUsed"`
	Attempts       int  `json:"attempts"`
	SourceAttempts int  `json:"sourceAttempts"`
	ResponseBytes  int  `json:"responseBytes"`
}

const evidenceControlLimit = 65536

func newEvidenceBoundary(path string) *evidenceBoundary { return &evidenceBoundary{path: path} }

func (b *evidenceBoundary) persist() bool {
	if b.failed {
		return false
	}
	if b.owner == nil {
		parent := filepath.Dir(b.path)
		real, err := filepath.EvalSymlinks(parent)
		info, statErr := os.Stat(parent)
		if !filepath.IsAbs(b.path) || filepath.Clean(b.path) != b.path || err != nil || real != parent || statErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			b.failed = true
			return false
		}
		b.owner, err = os.OpenFile(b.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			b.failed = true
			return false
		}
		dir, err := os.Open(parent)
		if err == nil {
			err = dir.Sync()
			_ = dir.Close()
		}
		if err != nil {
			b.failed = true
			return false
		}
	}
	data, err := json.Marshal(b.state)
	if err == nil {
		_, err = b.owner.WriteAt(data, 0)
	}
	if err == nil {
		err = b.owner.Truncate(int64(len(data)))
	}
	if err == nil {
		err = b.owner.Sync()
	}
	if err != nil {
		b.failed = true
		return false
	}
	return true
}

// decodeEvidenceObject rejects duplicate keys at every depth, arrays at the
// request root, trailing values and invalid UTF-8 through the canonical decoder.
func decodeEvidenceObject(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := evidenceValue(d)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("request must be object")
	}
	return m, nil
}

func evidenceValue(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	if delim == '{' {
		m := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			k, ok := key.(string)
			if !ok {
				return nil, errors.New("invalid key")
			}
			if _, exists := m[k]; exists {
				return nil, errors.New("duplicate key")
			}
			v, err := evidenceValue(d)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		_, err = d.Token()
		return m, err
	}
	if delim == '[' {
		var a []any
		for d.More() {
			v, err := evidenceValue(d)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		_, err = d.Token()
		return a, err
	}
	return nil, errors.New("invalid delimiter")
}

func evidenceIDOK(id any) bool {
	switch v := id.(type) {
	case string:
		var out bytes.Buffer
		e := json.NewEncoder(&out)
		e.SetEscapeHTML(false)
		if e.Encode(v) != nil {
			return false
		}
		return out.Len()-1 <= 64
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		return err == nil && n >= -9007199254740991 && n <= 9007199254740991
	default:
		return false
	}
}

// No Unwrap/Hijack passthrough: neither Flush nor ResponseController may bypass
// the final-size decision. Overflow never retains or releases partial evidence.
type evidenceCapture struct {
	header        http.Header
	body          bytes.Buffer
	status, limit int
	overflow      bool
}

func (w *evidenceCapture) Header() http.Header { return w.header }
func (w *evidenceCapture) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}
func (w *evidenceCapture) Flush() {}
func (w *evidenceCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.overflow || w.body.Len()+len(p) > w.limit {
		w.overflow = true
		w.body.Reset()
		return len(p), nil
	}
	return w.body.Write(p)
}

func refuseEvidence(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

func (b *evidenceBoundary) wrap(next http.Handler, backend string) http.Handler {
	if backend != "" && backend != "ci-evidence" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No standalone SSE stream/replay can release evidence outside a charged POST.
		if r.Method != http.MethodPost {
			refuseEvidence(w, http.StatusMethodNotAllowed)
			return
		}
		data, readErr := io.ReadAll(io.LimitReader(r.Body, 16385))
		_ = r.Body.Close()
		q, parseErr := decodeEvidenceObject(data)
		valid := readErr == nil && len(data) <= 16384 && parseErr == nil && q["jsonrpc"] == "2.0"
		method, _ := q["method"].(string)
		params, _ := q["params"].(map[string]any)
		name, _ := params["name"].(string)
		// Other routed servers never enter this wrapper. The unified safe-output
		// call is distinct from evidence and retains its existing behavior.
		if valid && backend == "" && method == "tools/call" && name == "safeoutputs___create_issue" {
			r.Body = io.NopCloser(bytes.NewReader(data))
			next.ServeHTTP(w, r)
			return
		}
		idOK := evidenceIDOK(q["id"])
		if method == "notifications/initialized" {
			_, exists := q["id"]
			idOK = !exists
		}
		control := valid && idOK && (method == "initialize" || method == "tools/list" || method == "ping" || method == "notifications/initialized")
		args, _ := params["arguments"].(map[string]any)
		expectedName := "read_ci_evidence"
		if backend == "" {
			expectedName = "ci-evidence___read_ci_evidence"
		}
		callOK := valid && idOK && method == "tools/call" && name == expectedName && len(q) == 4 && len(params) == 2
		b.mu.Lock()
		defer b.mu.Unlock()
		index := !control && callOK && args["operation"] == "index" && len(args) == 1 && !b.state.IndexUsed
		// Control responses (initialize, tools/list, ping) carry static tool metadata,
		// never evidence; they stay buffered (no streaming) under a separate ceiling so a
		// unified tools/list listing every backend cannot 502 the agent at startup.
		limit := evidenceControlLimit
		if !control {
			limit = 4096
		}
		if !control {
			if !b.persist() {
				refuseEvidence(w, http.StatusServiceUnavailable)
				return
			}
			if index {
				b.state.IndexUsed = true
				limit = 12288
			} else {
				if b.state.Attempts >= 8 {
					refuseEvidence(w, http.StatusTooManyRequests)
					return
				}
				b.state.Attempts++
				if args["kind"] == "source" {
					b.state.SourceAttempts++
				}
			}
			if !b.persist() {
				refuseEvidence(w, http.StatusServiceUnavailable)
				return
			}
			if !callOK || (!index && (!b.state.IndexUsed || args["operation"] != "read" && args["operation"] != "search")) || args["kind"] == "source" && b.state.SourceAttempts > 3 {
				refuseEvidence(w, http.StatusBadRequest)
				return
			}
		} else if !idOK {
			refuseEvidence(w, http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		capture := &evidenceCapture{header: make(http.Header), limit: limit}
		next.ServeHTTP(capture, r)
		if capture.overflow {
			refuseEvidence(w, http.StatusBadGateway)
			return
		}
		if !control && !index {
			if b.state.ResponseBytes+capture.body.Len() > 32768 {
				refuseEvidence(w, http.StatusTooManyRequests)
				return
			}
			b.state.ResponseBytes += capture.body.Len()
			if !b.persist() {
				refuseEvidence(w, http.StatusServiceUnavailable)
				return
			}
		}
		for key, values := range capture.header {
			w.Header()[key] = values
		}
		w.Header().Del("Transfer-Encoding")
		w.Header().Set("Content-Length", strconv.Itoa(capture.body.Len()))
		status := capture.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(capture.body.Bytes())
	})
}
