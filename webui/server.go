package webui

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qist/iptv-static-scan/cidr"
	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/output"
	"github.com/qist/iptv-static-scan/scanner"
)

type Server struct {
	jobs *jobStore
}

func NewServer() *Server {
	return &Server{jobs: newJobStore(0)}
}

func Start(addr string) error {
	return NewServer().Start(addr)
}

func (s *Server) Start(addr string) error {
	indexTmpl, err := template.New("index").Parse(webIndexHTML)
	if err != nil {
		return err
	}
	jobTmpl, err := template.New("job").Parse(webJobHTML)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		setNoCache(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = indexTmpl.Execute(w, defaultWebForm())
	})

	mux.HandleFunc("/job/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := normalizeJobID(strings.TrimPrefix(r.URL.Path, "/job/"))
		if id == "" {
			http.NotFound(w, r)
			return
		}
		initialJSON := "null"
		if snap, ok := s.jobs.getPersistedSnapshot(id); ok {
			if b, err := json.Marshal(snap); err == nil {
				initialJSON = string(b)
			}
		}
		setNoCache(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = jobTmpl.Execute(w, struct {
			JobID           string
			InitialSnapshot template.JS
		}{
			JobID:           id,
			InitialSnapshot: template.JS(initialJSON),
		})
	})

	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		cfg, cidrLines, writeToFile, err := configFromWebRequest(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}

		job := newScanJob(writeToFile, cfg.SuccessfulIPsFile)
		s.jobs.put(job)
		if err := s.jobs.save(); err != nil {
			log.Printf("保存任务记录失败: %v", err)
		}
		go runWebScan(s.jobs, job, cfg, cidrLines, writeToFile)

		writeJSON(w, http.StatusOK, map[string]any{"id": job.ID})
	})

	mux.HandleFunc("/api/job/", func(w http.ResponseWriter, r *http.Request) {
		setNoCache(w)
		id := normalizeJobID(strings.TrimPrefix(r.URL.Path, "/api/job/"))
		switch r.Method {
		case http.MethodGet:
			if snap, ok := s.jobs.getPersistedSnapshot(id); ok {
				writeJSON(w, http.StatusOK, snap)
				return
			}
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "job not found"})
			return
		case http.MethodDelete:
			force := strings.TrimSpace(r.URL.Query().Get("force")) == "1"
			if err := s.jobs.delete(id, force); err != nil {
				if err == errJobNotFound {
					if ok := s.jobs.deletePersisted(id); ok {
						writeJSON(w, http.StatusOK, map[string]any{"ok": true})
						return
					}
					writeJSON(w, http.StatusNotFound, map[string]any{"error": "job not found"})
					return
				}
				if err == errJobRunning {
					writeJSON(w, http.StatusConflict, map[string]any{"error": "job is running"})
					return
				}
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		setNoCache(w)
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		limit := 50
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 500 {
				limit = v
			}
		}
		items := s.jobs.list(status, limit)
		writeJSON(w, http.StatusOK, items)
	})

	log.Printf("Web UI 启动: http://%s/\n", addr)
	return http.ListenAndServe(addr, mux)
}

type scanJob struct {
	ID                string
	CreatedAt         time.Time
	StartedAt         time.Time
	FinishedAt        time.Time
	Status            string
	Error             string
	WriteToFile       bool
	SuccessfulIPsFile string

	mu         sync.Mutex
	successSet map[string]struct{}
	Success    []string
}

func newScanJob(writeToFile bool, successfulIPsFile string) *scanJob {
	return &scanJob{
		ID:                newJobID(),
		CreatedAt:         time.Now(),
		Status:            "queued",
		WriteToFile:       writeToFile,
		SuccessfulIPsFile: successfulIPsFile,
		successSet:        map[string]struct{}{},
	}
}

func (j *scanJob) addSuccess(item string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.successSet[item]; ok {
		return
	}
	j.successSet[item] = struct{}{}
	j.Success = append(j.Success, item)
}

func (j *scanJob) snapshot() scanJobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	successCopy := make([]string, len(j.Success))
	copy(successCopy, j.Success)
	return scanJobSnapshot{
		ID:                j.ID,
		CreatedAt:         j.CreatedAt,
		StartedAt:         j.StartedAt,
		FinishedAt:        j.FinishedAt,
		Status:            j.Status,
		Error:             j.Error,
		WriteToFile:       j.WriteToFile,
		SuccessfulIPsFile: j.SuccessfulIPsFile,
		SuccessCount:      len(j.Success),
		Success:           successCopy,
	}
}

type scanJobSnapshot struct {
	ID                string    `json:"id"`
	CreatedAt         time.Time `json:"createdAt"`
	StartedAt         time.Time `json:"startedAt"`
	FinishedAt        time.Time `json:"finishedAt"`
	Status            string    `json:"status"`
	Error             string    `json:"error"`
	WriteToFile       bool      `json:"writeToFile"`
	SuccessfulIPsFile string    `json:"successfulIPsFile"`
	SuccessCount      int       `json:"successCount"`
	Success           []string  `json:"success"`
}

type scanJobListItem struct {
	ID                string    `json:"id"`
	CreatedAt         time.Time `json:"createdAt"`
	StartedAt         time.Time `json:"startedAt"`
	FinishedAt        time.Time `json:"finishedAt"`
	Status            string    `json:"status"`
	Error             string    `json:"error"`
	SuccessCount      int       `json:"successCount"`
	WriteToFile       bool      `json:"writeToFile"`
	SuccessfulIPsFile string    `json:"successfulIPsFile"`
}

type jobStore struct {
	mu       sync.RWMutex
	jobs     map[string]*scanJob
	order    []string
	maxItems int
	path     string
}

func newJobStore(maxItems int) *jobStore {
	if maxItems < 0 {
		maxItems = 200
	}
	s := &jobStore{
		jobs:     map[string]*scanJob{},
		order:    make([]string, 0, maxItems),
		maxItems: maxItems,
		path:     defaultJobStorePath(),
	}
	s.load()
	return s
}

func (s *jobStore) put(job *scanJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[job.ID]; !exists {
		s.order = append(s.order, job.ID)
	}
	s.jobs[job.ID] = job
	if s.maxItems > 0 {
		s.pruneLocked()
	}
	s.saveAsync()
}

func (s *jobStore) pruneLocked() {
	if s.maxItems <= 0 {
		return
	}
	if len(s.order) <= s.maxItems {
		return
	}
	excess := len(s.order) - s.maxItems
	if excess <= 0 {
		return
	}

	toRemove := make([]string, 0, excess)
	for _, id := range s.order {
		if len(toRemove) >= excess {
			break
		}
		job, ok := s.jobs[id]
		if !ok {
			toRemove = append(toRemove, id)
			continue
		}
		job.mu.Lock()
		status := job.Status
		job.mu.Unlock()
		if status == "done" || status == "error" {
			toRemove = append(toRemove, id)
		}
	}
	for _, id := range toRemove {
		delete(s.jobs, id)
	}
	if len(toRemove) > 0 {
		keep := make([]string, 0, len(s.order)-len(toRemove))
		rm := map[string]struct{}{}
		for _, id := range toRemove {
			rm[id] = struct{}{}
		}
		for _, id := range s.order {
			if _, ok := rm[id]; ok {
				continue
			}
			keep = append(keep, id)
		}
		s.order = keep
	}

	for len(s.order) > s.maxItems {
		id := s.order[0]
		job, ok := s.jobs[id]
		if !ok {
			s.order = s.order[1:]
			continue
		}
		job.mu.Lock()
		status := job.Status
		job.mu.Unlock()
		if status == "running" || status == "queued" {
			break
		}
		s.order = s.order[1:]
		delete(s.jobs, id)
	}
}

func (s *jobStore) get(id string) (*scanJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	return job, ok
}

func (s *jobStore) list(status string, limit int) []scanJobListItem {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	snaps := readPersistedSnapshots(candidateJobStorePaths(s.path))
	items := make([]scanJobListItem, 0, len(snaps))
	for _, snap := range snaps {
		if status != "" && snap.Status != status {
			continue
		}
		items = append(items, scanJobListItem{
			ID:                snap.ID,
			CreatedAt:         snap.CreatedAt,
			StartedAt:         snap.StartedAt,
			FinishedAt:        snap.FinishedAt,
			Status:            snap.Status,
			Error:             snap.Error,
			SuccessCount:      snap.SuccessCount,
			WriteToFile:       snap.WriteToFile,
			SuccessfulIPsFile: snap.SuccessfulIPsFile,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})

	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

var errJobNotFound = fmt.Errorf("job not found")
var errJobRunning = fmt.Errorf("job is running")

func (s *jobStore) delete(id string, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return errJobNotFound
	}
	job.mu.Lock()
	status := job.Status
	job.mu.Unlock()
	if (status == "running" || status == "queued") && !force {
		return errJobRunning
	}
	delete(s.jobs, id)
	keep := make([]string, 0, len(s.order))
	for _, existing := range s.order {
		if existing == id {
			continue
		}
		keep = append(keep, existing)
	}
	s.order = keep
	s.saveAsync()
	return nil
}

func setNoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

type persistedJobStore struct {
	Version int               `json:"version"`
	SavedAt time.Time         `json:"savedAt"`
	Items   []scanJobSnapshot `json:"items"`
}

func defaultJobStorePath() string {
	if v := strings.TrimSpace(os.Getenv("IPTV_WEBUI_JOBS_PATH")); v != "" {
		_ = os.MkdirAll(filepath.Dir(v), 0755)
		return v
	}

	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, ".webui", "jobs.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		if !strings.Contains(base, string(filepath.Separator)+"go-build") && !strings.HasPrefix(base, os.TempDir()) {
			dir := filepath.Join(base, ".webui")
			_ = os.MkdirAll(dir, 0755)
			return filepath.Join(dir, "jobs.json")
		}
	}

	if wd, err := os.Getwd(); err == nil {
		dir := filepath.Join(wd, ".webui")
		_ = os.MkdirAll(dir, 0755)
		return filepath.Join(dir, "jobs.json")
	}

	dir := ".webui"
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "jobs.json")
}

func candidateJobStorePaths(primary string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	add(primary)
	if v := strings.TrimSpace(os.Getenv("IPTV_WEBUI_JOBS_PATH")); v != "" {
		add(v)
	}
	if wd, err := os.Getwd(); err == nil {
		add(filepath.Join(wd, ".webui", "jobs.json"))
	}
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		add(filepath.Join(base, ".webui", "jobs.json"))
	}
	return out
}

func normalizeJobID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.Trim(id, "/")
	return id
}

func (s *jobStore) load() {
	items := readPersistedSnapshots(candidateJobStorePaths(s.path))
	if len(items) == 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, snap := range items {
		job := &scanJob{
			ID:                snap.ID,
			CreatedAt:         snap.CreatedAt,
			StartedAt:         snap.StartedAt,
			FinishedAt:        snap.FinishedAt,
			Status:            snap.Status,
			Error:             snap.Error,
			WriteToFile:       snap.WriteToFile,
			SuccessfulIPsFile: snap.SuccessfulIPsFile,
			successSet:        map[string]struct{}{},
			Success:           append([]string(nil), snap.Success...),
		}
		for _, v := range job.Success {
			job.successSet[v] = struct{}{}
		}
		if job.Status == "running" || job.Status == "queued" {
			job.Status = "interrupted"
			if job.Error == "" {
				job.Error = "服务已重启，任务中断"
			} else {
				job.Error = job.Error + " | 服务已重启，任务中断"
			}
			if job.FinishedAt.IsZero() {
				job.FinishedAt = now
			}
		}
		s.jobs[job.ID] = job
		s.order = append(s.order, job.ID)
	}
	if s.maxItems > 0 {
		s.pruneLocked()
	}
}

func (s *jobStore) getPersistedSnapshot(id string) (scanJobSnapshot, bool) {
	id = normalizeJobID(id)
	if id == "" {
		return scanJobSnapshot{}, false
	}
	for _, item := range readPersistedSnapshots(candidateJobStorePaths(s.path)) {
		if item.ID == id {
			return item, true
		}
	}
	return scanJobSnapshot{}, false
}

func (s *jobStore) deletePersisted(id string) bool {
	id = normalizeJobID(id)
	if id == "" {
		return false
	}
	removed := false
	for _, path := range candidateJobStorePaths(s.path) {
		if deletePersistedAtPath(path, id) {
			removed = true
		}
	}
	return removed
}

func readPersistedSnapshots(paths []string) []scanJobSnapshot {
	itemsByID := map[string]scanJobSnapshot{}
	for _, path := range paths {
		p, ok := readPersistedStore(path)
		if !ok {
			continue
		}
		for _, item := range p.Items {
			existing, exists := itemsByID[item.ID]
			if !exists || item.CreatedAt.After(existing.CreatedAt) || item.FinishedAt.After(existing.FinishedAt) {
				itemsByID[item.ID] = item
			}
		}
	}
	items := make([]scanJobSnapshot, 0, len(itemsByID))
	for _, item := range itemsByID {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items
}

func readPersistedStore(path string) (persistedJobStore, bool) {
	if strings.TrimSpace(path) == "" {
		return persistedJobStore{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return persistedJobStore{}, false
	}
	var p persistedJobStore
	if err := json.Unmarshal(b, &p); err != nil {
		return persistedJobStore{}, false
	}
	if p.Version != 1 {
		return persistedJobStore{}, false
	}
	return p, true
}

func deletePersistedAtPath(path, id string) bool {
	p, ok := readPersistedStore(path)
	if !ok {
		return false
	}
	keep := make([]scanJobSnapshot, 0, len(p.Items))
	removed := false
	for _, item := range p.Items {
		if item.ID == id {
			removed = true
			continue
		}
		keep = append(keep, item)
	}
	if !removed {
		return false
	}
	p.Items = keep
	p.SavedAt = time.Now()
	out, err := json.Marshal(p)
	if err != nil {
		return false
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false
	}
	tmp, err := os.CreateTemp(dir, "jobs-*.json")
	if err != nil {
		return false
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(out)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmpName)
		return false
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return false
	}
	return true
}

func (s *jobStore) saveAsync() {
	go func() {
		_ = s.save()
	}()
}

func (s *jobStore) save() error {
	if s.path == "" {
		return nil
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	s.mu.RLock()
	ids := make([]string, 0, len(s.order))
	ids = append(ids, s.order...)
	jobs := make([]*scanJob, 0, len(ids))
	cleanIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		job, ok := s.jobs[id]
		if !ok {
			continue
		}
		cleanIDs = append(cleanIDs, id)
		jobs = append(jobs, job)
	}
	s.mu.RUnlock()

	items := make([]scanJobSnapshot, 0, len(jobs))
	for i, job := range jobs {
		snap := job.snapshot()
		if snap.ID == "" {
			snap.ID = cleanIDs[i]
		}
		items = append(items, snap)
	}
	p := persistedJobStore{Version: 1, SavedAt: time.Now(), Items: items}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "jobs-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil {
		_ = os.Remove(tmpName)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(tmpName)
		return cerr
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

type webFormDefaults struct {
	Ports                string
	URLPaths             string
	NonPortsPath         string
	MaxConcurrentRequest int
	TimeOut              int
	DownSize             string
	FileBufferSize       int
	WriteToFile          bool
	DownloadTS           bool
	Outputs              bool
	LogEnabled           bool
	SuccessfulIPsFile    string
	UserAgent            string
	CIDRInput            string
}

func defaultWebForm() webFormDefaults {
	return webFormDefaults{
		Ports:                "80",
		URLPaths:             "player-live.html",
		NonPortsPath:         "",
		MaxConcurrentRequest: 2000,
		TimeOut:              10,
		DownSize:             "0.2",
		FileBufferSize:       200,
		WriteToFile:          false,
		DownloadTS:           false,
		Outputs:              true,
		LogEnabled:           false,
		SuccessfulIPsFile:    "successful_zubo.txt",
		UserAgent:            "okhttp/3.8.10",
		CIDRInput:            "",
	}
}

func configFromWebRequest(r *http.Request) (*config.Config, []string, bool, error) {
	if err := r.ParseForm(); err != nil {
		return nil, nil, false, err
	}

	ports := splitList(r.Form.Get("ports"))
	if len(ports) == 0 {
		ports = []string{"80"}
	}

	urlPaths := splitList(r.Form.Get("urlPaths"))
	if len(urlPaths) == 0 {
		urlPaths = []string{"player-live.html"}
	}

	nonPortsPath := splitList(r.Form.Get("nonPortsPath"))

	maxConcurrentRequest, err := parseIntWithDefault(r.Form.Get("maxConcurrentRequests"), 2000)
	if err != nil {
		return nil, nil, false, fmt.Errorf("maxConcurrentRequests 无效: %w", err)
	}
	if maxConcurrentRequest <= 0 {
		return nil, nil, false, fmt.Errorf("maxConcurrentRequests 必须大于 0")
	}

	timeoutSec, err := parseIntWithDefault(r.Form.Get("timeOut"), 10)
	if err != nil {
		return nil, nil, false, fmt.Errorf("timeOut 无效: %w", err)
	}
	if timeoutSec <= 0 {
		return nil, nil, false, fmt.Errorf("timeOut 必须大于 0")
	}

	downSize, err := parseFloatWithDefault(r.Form.Get("downSize"), 0.2)
	if err != nil {
		return nil, nil, false, fmt.Errorf("downSize 无效: %w", err)
	}
	if downSize <= 0 {
		return nil, nil, false, fmt.Errorf("downSize 必须大于 0")
	}

	fileBufferSize, err := parseIntWithDefault(r.Form.Get("fileBufferSize"), 200)
	if err != nil {
		return nil, nil, false, fmt.Errorf("fileBufferSize 无效: %w", err)
	}
	if fileBufferSize <= 0 {
		return nil, nil, false, fmt.Errorf("fileBufferSize 必须大于 0")
	}

	successfulIPsFile := strings.TrimSpace(r.Form.Get("successfulIPsFile"))
	if successfulIPsFile == "" {
		successfulIPsFile = "successful_zubo.txt"
	}

	userAgent := strings.TrimSpace(r.Form.Get("userAgent"))
	if userAgent == "" {
		userAgent = "okhttp/3.8.10"
	}

	cfg := &config.Config{
		Ports:                ports,
		URLPaths:             urlPaths,
		NonPortsPath:         nonPortsPath,
		MaxConcurrentRequest: maxConcurrentRequest,
		SuccessfulIPsFile:    successfulIPsFile,
		UAHeaders:            map[string][]string{"User-Agent": {userAgent}},
		CIDRFile:             "",
		TimeOut:              timeoutSec,
		DownSize:             downSize,
		FileBufferSize:       fileBufferSize,
		DownloadTS:           r.Form.Get("downloadTS") == "on",
		Outputs:              r.Form.Get("outputs") == "on",
		LogEnabled:           r.Form.Get("logEnabled") == "on",
	}

	cidrText := r.Form.Get("cidrInput")
	cidrLines := splitList(cidrText)
	if len(cidrLines) == 0 {
		return nil, nil, false, fmt.Errorf("CIDR 输入不能为空（支持 CIDR、单 IP、IP 范围、域名、ip:port）")
	}

	writeToFile := r.Form.Get("writeToFile") == "on"
	return cfg, cidrLines, writeToFile, nil
}

func runWebScan(store *jobStore, job *scanJob, cfg *config.Config, cidrLines []string, writeToFile bool) {
	job.mu.Lock()
	job.Status = "running"
	job.StartedAt = time.Now()
	job.mu.Unlock()
	if err := store.save(); err != nil {
		log.Printf("保存任务记录失败: %v", err)
	}

	if !cfg.LogEnabled {
		log.SetOutput(io.Discard)
	}

	if writeToFile {
		if err := output.ClearFileContent(cfg.SuccessfulIPsFile); err != nil {
			job.mu.Lock()
			job.Status = "error"
			job.Error = err.Error()
			job.FinishedAt = time.Now()
			job.mu.Unlock()
			if err := store.save(); err != nil {
				log.Printf("保存任务记录失败: %v", err)
			}
			return
		}
	}

	successfulIPsCh := make(chan string, cfg.FileBufferSize)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		lastSave := time.Now()
		const saveInterval = 2 * time.Second
		for successfulIP := range successfulIPsCh {
			job.addSuccess(successfulIP)
			if time.Since(lastSave) >= saveInterval {
				store.saveAsync()
				lastSave = time.Now()
			}
			if writeToFile {
				if err := output.AppendToFile(cfg.SuccessfulIPsFile, successfulIP); err != nil {
					log.Printf("写入成功的IP到文件失败: %v\n", err)
				}
			}
		}
		store.saveAsync()
	}()

	bufferSize := cfg.MaxConcurrentRequest * 1024
	workerPool := scanner.NewWorkerPool(cfg.MaxConcurrentRequest, bufferSize)
	workerPool.Start()

	cidrInput := strings.Join(cidrLines, "\n")
	if err := cidr.ParseCIDRReader(workerPool, cfg, strings.NewReader(cidrInput), successfulIPsCh); err != nil {
		close(workerPool.TaskQueue)
		workerPool.Wait()
		close(successfulIPsCh)
		wg.Wait()

		job.mu.Lock()
		job.Status = "error"
		job.Error = err.Error()
		job.FinishedAt = time.Now()
		job.mu.Unlock()
		if err := store.save(); err != nil {
			log.Printf("保存任务记录失败: %v", err)
		}
		return
	}

	close(workerPool.TaskQueue)
	workerPool.Wait()
	close(successfulIPsCh)
	wg.Wait()

	if err := output.DeleteStreamFiles(); err != nil {
		job.mu.Lock()
		job.Status = "error"
		job.Error = err.Error()
		job.FinishedAt = time.Now()
		job.mu.Unlock()
		if err := store.save(); err != nil {
			log.Printf("保存任务记录失败: %v", err)
		}
		return
	}

	job.mu.Lock()
	job.Status = "done"
	job.FinishedAt = time.Now()
	job.mu.Unlock()
	if err := store.save(); err != nil {
		log.Printf("保存任务记录失败: %v", err)
	}
}

func splitList(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, ",", "\n")
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func parseIntWithDefault(s string, def int) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	return strconv.Atoi(s)
}

func parseFloatWithDefault(s string, def float64) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	return strconv.ParseFloat(s, 64)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newJobID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

const webIndexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>IPTV Static Scan</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; margin: 18px; }
    .row { display: flex; gap: 16px; flex-wrap: wrap; }
    .col { flex: 1; min-width: 320px; }
    label { display: block; font-weight: 600; margin-top: 12px; }
    textarea, input[type="text"], input[type="number"] { width: 100%; box-sizing: border-box; padding: 8px; margin-top: 6px; }
    textarea { min-height: 110px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .small { font-size: 12px; color: #555; margin-top: 6px; }
    .actions { margin-top: 16px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    button { padding: 10px 14px; cursor: pointer; }
    .error { color: #b00020; white-space: pre-wrap; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #eee; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #fafafa; }
    .muted { color: #666; font-size: 12px; }
    .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #f2f2f2; font-size: 12px; }
    .pill.done { background: #e7f6ea; }
    .pill.running { background: #e8f0fe; }
    .pill.error { background: #fde7e9; }
  </style>
</head>
<body>
  <h1>IPTV Static Scan</h1>

  <h2>新建扫描</h2>
  <div class="row">
    <div class="col">
      <label>CIDR / IP / 域名 / ip:port（每行一条）</label>
      <textarea id="cidrInput" placeholder="例：&#10;1.2.3.4/32&#10;1.2.3.4:80&#10;1.2.3.4-1.2.3.20&#10;example.com"></textarea>
      <div class="small">必填。支持 CIDR、单 IP、IP 范围、域名、ip:port。</div>
    </div>
    <div class="col">
      <label>端口（每行一个，支持 80 或 1000-40000）</label>
      <textarea id="ports">{{.Ports}}</textarea>
      <label>URL Paths（每行一个）</label>
      <textarea id="urlPaths">{{.URLPaths}}</textarea>
      <label>非循环端口路径（每行一个，格式 端口/路径）</label>
      <textarea id="nonPortsPath" placeholder="例：&#10;14891/rtp/239.77.0.2:5146&#10;81/gitv_live/G_BINGQIKJ-CQ/G_BINGQIKJ-CQ.m3u8&#10;5003/cctv3.m3u8&#10;80/live/program/live/cctv1hd8m/8000000/mnf.m3u8">{{.NonPortsPath}}</textarea>
      <div class="small">参考 config.yaml 的 non_ports_path，例如 14891/rtp/239.77.0.2:5146 或 80/live/program/live/cctv1hd8m/8000000/mnf.m3u8。</div>
    </div>
  </div>

  <div class="row">
    <div class="col">
      <label>并发数 maxConcurrentRequests</label>
      <input id="maxConcurrentRequests" type="number" min="1" value="{{.MaxConcurrentRequest}}" />
      <label>超时 timeOut（秒）</label>
      <input id="timeOut" type="number" min="1" value="{{.TimeOut}}" />
      <label>下载检测大小 downSize（MB）</label>
      <input id="downSize" type="text" value="{{.DownSize}}" />
      <label>写文件缓冲 fileBufferSize</label>
      <input id="fileBufferSize" type="number" min="1" value="{{.FileBufferSize}}" />
    </div>
    <div class="col">
      <div class="actions">
        <label><input id="writeToFile" type="checkbox" {{if .WriteToFile}}checked{{end}} /> 写入文件</label>
        <label><input id="downloadTS" type="checkbox" {{if .DownloadTS}}checked{{end}} /> download_ts</label>
        <label><input id="outputs" type="checkbox" {{if .Outputs}}checked{{end}} /> outputs</label>
        <label><input id="logEnabled" type="checkbox" {{if .LogEnabled}}checked{{end}} /> logEnabled</label>
      </div>
      <label>输出文件 successfulIPsFile</label>
      <input id="successfulIPsFile" type="text" value="{{.SuccessfulIPsFile}}" />
      <label>User-Agent</label>
      <input id="userAgent" type="text" value="{{.UserAgent}}" />
    </div>
  </div>

  <div class="actions">
    <button id="startBtn">开始扫描</button>
    <div id="status"></div>
  </div>
  <div class="error" id="error"></div>

  <h2>历史任务</h2>
  <div class="muted">任务列表直接从 jobs.json 读取。点击 JobID 进入详情页。</div>
  <div class="actions">
    <button id="refreshBtn">刷新</button>
    <span class="muted" id="historyMeta"></span>
  </div>
  <table>
    <thead>
      <tr>
        <th>JobID</th>
        <th>状态</th>
        <th>成功数</th>
        <th>开始/结束</th>
        <th>写文件</th>
        <th>操作</th>
        <th>错误</th>
      </tr>
    </thead>
    <tbody id="historyBody"></tbody>
  </table>

  <script>
    const $ = (id) => document.getElementById(id);
    const syncWriteToFileUI = () => {
      const enabled = $('writeToFile').checked;
      $('successfulIPsFile').disabled = !enabled;
    };
    $('writeToFile').addEventListener('change', syncWriteToFileUI);
    syncWriteToFileUI();

    const esc = (s) => String(s == null ? '' : s)
      .replaceAll('&','&amp;')
      .replaceAll('<','&lt;')
      .replaceAll('>','&gt;')
      .replaceAll('"','&quot;')
      .replaceAll("'","&#39;");

    const pill = (status) => {
      const s = String(status || '');
      const cls = s === 'done' ? 'done' : (s === 'error' ? 'error' : 'running');
      return '<span class="pill ' + cls + '">' + esc(s) + '</span>';
    };

    const fmtTime = (t) => {
      if (!t) return '';
      return String(t).replace('T',' ').replace('Z','');
    };

    const loadHistory = async () => {
      try {
        const resp = await fetch('/api/jobs?limit=200');
        const items = await resp.json();
        const body = $('historyBody');
        body.innerHTML = '';
        const sorted = Array.isArray(items) ? items : [];
        for (const it of sorted) {
          const id = it.id;
          const status = it.status;
          const successCount = it.successCount || 0;
          const start = fmtTime(it.startedAt);
          const end = fmtTime(it.finishedAt);
          const writeToFile = it.writeToFile ? ('是: ' + (it.successfulIPsFile || '')) : '否';
          const err = it.error || '';
          const canDelete = (status === 'done' || status === 'error' || status === 'interrupted');
          const tr = document.createElement('tr');
          tr.innerHTML =
            '<td><a href="/job/' + encodeURIComponent(id) + '">' + esc(id) + '</a><div class="muted">' + fmtTime(it.createdAt) + '</div></td>' +
            '<td>' + pill(status) + '</td>' +
            '<td>' + esc(successCount) + '</td>' +
            '<td><div class="muted">开始: ' + esc(start) + '</div><div class="muted">结束: ' + esc(end) + '</div></td>' +
            '<td>' + esc(writeToFile) + '</td>' +
            '<td>' + (canDelete ? ('<button data-del="' + esc(id) + '">删除</button>') : '<span class="muted">-</span>') + '</td>' +
            '<td class="muted">' + esc(err) + '</td>';
          body.appendChild(tr);
        }
        $('historyMeta').textContent = '任务数量: ' + sorted.length;
        document.querySelectorAll('button[data-del]').forEach((btn) => {
          btn.addEventListener('click', async (e) => {
            const id = e.currentTarget.getAttribute('data-del');
            if (!id) return;
            try {
              const resp = await fetch('/api/job/' + encodeURIComponent(id), { method: 'DELETE' });
              if (!resp.ok) {
                const data = await resp.json().catch(() => ({}));
                throw new Error(data && data.error ? data.error : ('HTTP ' + resp.status));
              }
              loadHistory();
            } catch (err) {
              $('historyMeta').textContent = '删除失败: ' + String(err && err.message ? err.message : err);
            }
          });
        });
      } catch (e) {
        $('historyMeta').textContent = '拉取失败: ' + String(e && e.message ? e.message : e);
      }
    };

    $('refreshBtn').addEventListener('click', loadHistory);
    loadHistory();
    setInterval(loadHistory, 3000);

    $('startBtn').addEventListener('click', async () => {
      $('error').textContent = '';
      $('status').textContent = '提交中...';
      const params = new URLSearchParams();
      params.set('cidrInput', $('cidrInput').value);
      params.set('ports', $('ports').value);
      params.set('urlPaths', $('urlPaths').value);
      params.set('nonPortsPath', $('nonPortsPath').value);
      params.set('maxConcurrentRequests', $('maxConcurrentRequests').value);
      params.set('timeOut', $('timeOut').value);
      params.set('downSize', $('downSize').value);
      params.set('fileBufferSize', $('fileBufferSize').value);
      params.set('successfulIPsFile', $('successfulIPsFile').value);
      params.set('userAgent', $('userAgent').value);
      if ($('writeToFile').checked) params.set('writeToFile', 'on');
      if ($('downloadTS').checked) params.set('downloadTS', 'on');
      if ($('outputs').checked) params.set('outputs', 'on');
      if ($('logEnabled').checked) params.set('logEnabled', 'on');

      try {
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: params.toString()
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data && data.error ? data.error : ('HTTP ' + resp.status));
        $('status').innerHTML = '已创建任务：<a href="/job/' + encodeURIComponent(data.id) + '">' + esc(data.id) + '</a>，扫描已在后台开始';
        loadHistory();
      } catch (e) {
        $('status').textContent = '';
        $('error').textContent = String(e && e.message ? e.message : e);
      }
    });
  </script>
</body>
</html>`

const webJobHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>扫描任务 {{.JobID}}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; margin: 18px; }
    .meta { color: #444; }
    .err { color: #b00020; white-space: pre-wrap; }
    pre { background: #fafafa; border: 1px solid #eee; padding: 10px; overflow: auto; }
    a { color: #2563eb; }
  </style>
</head>
<body>
  <h1>扫描任务</h1>
  <div class="meta">JobID: <code>{{.JobID}}</code></div>
  <div class="meta"><a href="/">返回首页</a></div>
  <div id="status" class="meta"></div>
  <div id="meta" class="meta"></div>
  <div id="err" class="err"></div>
  <h2>成功列表（独立显示）</h2>
  <div class="meta" id="count"></div>
  <pre id="success"></pre>
  <script>
    const jobID = {{printf "%q" .JobID}};
    const initialSnapshot = {{.InitialSnapshot}};
    const statusEl = document.getElementById('status');
    const metaEl = document.getElementById('meta');
    const errEl = document.getElementById('err');
    const successEl = document.getElementById('success');
    const countEl = document.getElementById('count');
    let stopped = false;

    const fmtTime = (t) => {
      if (!t) return '';
      return String(t).replace('T',' ').replace('Z','');
    };

    const render = (snap) => {
      statusEl.textContent = '状态: ' + snap.status + (snap.startedAt ? (' | 开始: ' + fmtTime(snap.startedAt)) : '') + (snap.finishedAt ? (' | 结束: ' + fmtTime(snap.finishedAt)) : '');
      metaEl.textContent = '写入文件: ' + (snap.writeToFile ? ('是 (' + (snap.successfulIPsFile || '') + ')') : '否');
      errEl.textContent = snap.error || '';
      countEl.textContent = '成功数量: ' + (snap.success ? snap.success.length : 0);
      successEl.textContent = (snap.success || []).join('\n');
    };

    if (initialSnapshot) {
      render(initialSnapshot);
      if (initialSnapshot.status !== 'running' && initialSnapshot.status !== 'queued') {
        stopped = true;
      }
    }

    const poll = async () => {
      if (stopped) return;
      try {
        const resp = await fetch('/api/job/' + jobID);
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          const msg = data && data.error ? data.error : ('HTTP ' + resp.status);
          errEl.textContent = msg + '（任务可能已被删除/服务已重启）';
          statusEl.textContent = '状态: 不存在';
          metaEl.textContent = '';
          countEl.textContent = '成功数量: 0';
          successEl.textContent = '';
          stopped = true;
          return;
        }
        const snap = await resp.json();
        render(snap);
        if (snap.status === 'running' || snap.status === 'queued') {
          setTimeout(poll, 1000);
        }
      } catch (e) {
        errEl.textContent = String(e && e.message ? e.message : e);
        setTimeout(poll, 1500);
      }
    };

    poll();
  </script>
</body>
</html>`
