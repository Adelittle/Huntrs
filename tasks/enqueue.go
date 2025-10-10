package tasks

import (
	"encoding/json"
	"log"

	"github.com/hibiken/asynq"
)

const (
	redisAddr = "127.0.0.1:6379"
)

var asynqClient = asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})

const (
	TypeSubdomainScan = "scan:subdomain"
	TypeHttpxScan     = "scan:httpx"
	TypeDirectoryScan = "scan:directory"
)

type SubdomainScanPayload struct {
	Targets  []string `json:"targets"`
	Tool     string   `json:"tool"`
	FileName string   `json:"fileName"`
	Username string   `json:"username"`
}

// HttpxScanPayload sekarang menyertakan semua opsi baru.
type HttpxScanPayload struct {
	Targets           []string `json:"targets"`
	FileName          string   `json:"fileName"`
	Username          string   `json:"username"`
	Threads           string   `json:"threads"`
	Timeout           string   `json:"timeout"`
	Options           []string `json:"options"`
	NoColor           bool     `json:"noColor"`
	FollowRedirects   bool     `json:"followRedirects"`
	Method            string   `json:"method"`
	FilterStatusCodes string   `json:"filterStatusCodes"`
}

type DirectoryScanPayload struct {
	Targets        []string `json:"targets"`
	TargetMode     string   `json:"targetMode"`
	Wordlist       string   `json:"wordlist"`
	WordlistOption string   `json:"wordlistOption"`
	WordlistURL    string   `json:"wordlistUrl"`
	FileName       string   `json:"fileName"`
	Username       string   `json:"username"`
	Extensions     string   `json:"extensions"`
	Threads        string   `json:"threads"`
	Delay          string   `json:"delay"`
	MatchCodes     string   `json:"matchCodes"`
	MatchWords     string   `json:"matchWords"`
	FilterWords    string   `json:"filterWords"`
	Timeout        string   `json:"timeout"`
	Recursive      bool     `json:"recursive"`
	RecursionDepth string   `json:"recursionDepth"`
	Headers        []string `json:"headers"`
	Method         string   `json:"method"`
	OutputFormat   string   `json:"outputFormat"`
	UserAgent      string   `json:"userAgent"`
	UserAgentLabel string   `json:"userAgentLabel"`
}

func EnqueueSubdomainScan(payload SubdomainScanPayload) (*asynq.TaskInfo, error) {
	p, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: tidak dapat me-marshal payload subdomain: %v", err)
		return nil, err
	}
	task := asynq.NewTask(TypeSubdomainScan, p)
	info, err := asynqClient.Enqueue(task)
	if err != nil {
		log.Printf("ERROR: tidak dapat menambahkan tugas subdomain ke antrian: %v", err)
		return nil, err
	}
	return info, nil
}

// EnqueueHttpxScan membuat dan menambahkan tugas pemindaian httpx baru.
func EnqueueHttpxScan(payload HttpxScanPayload) (*asynq.TaskInfo, error) {
	p, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: could not marshal httpx payload: %v", err)
		return nil, err
	}
	task := asynq.NewTask(TypeHttpxScan, p)
	info, err := asynqClient.Enqueue(task)
	if err != nil {
		log.Printf("ERROR: could not enqueue httpx task: %v", err)
		return nil, err
	}
	return info, nil
}

func EnqueueDirectoryScan(payload DirectoryScanPayload) (*asynq.TaskInfo, error) {
	p, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: tidak dapat me-marshal payload direktori: %v", err)
		return nil, err
	}
	task := asynq.NewTask(TypeDirectoryScan, p)
	info, err := asynqClient.Enqueue(task)
	if err != nil {
		log.Printf("ERROR: tidak dapat menambahkan tugas direktori ke antrian: %v", err)
		return nil, err
	}
	return info, nil
}

// CancelTask membatalkan pemrosesan tugas yang sedang berjalan.
func CancelTask(queue, taskID string) error {
	inspector := asynq.NewInspector(asynq.RedisClientOpt{Addr: redisAddr})
	return inspector.CancelProcessing(queue, taskID)
}
