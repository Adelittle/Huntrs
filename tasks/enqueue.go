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
	Target     string   `json:"target"`
	Wordlist   string   `json:"wordlist"`
	FileName   string   `json:"fileName"`
	Username   string   `json:"username"`
	Extensions string   `json:"extensions"`
	Threads    string   `json:"threads"`
	Delay      string   `json:"delay"`
	MatchCodes string   `json:"matchCodes"`
	Recursive  bool     `json:"recursive"`
	Headers    []string `json:"headers"`
}

func EnqueueSubdomainScan(payload SubdomainScanPayload) {
	p, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: tidak dapat me-marshal payload subdomain: %v", err)
		return
	}
	task := asynq.NewTask(TypeSubdomainScan, p)
	_, err = asynqClient.Enqueue(task)
	if err != nil {
		log.Printf("ERROR: tidak dapat menambahkan tugas subdomain ke antrian: %v", err)
	}
}

// EnqueueHttpxScan membuat dan menambahkan tugas pemindaian httpx baru.
func EnqueueHttpxScan(payload HttpxScanPayload) {
	p, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: could not marshal httpx payload: %v", err)
		return
	}
	task := asynq.NewTask(TypeHttpxScan, p)
	_, err = asynqClient.Enqueue(task)
	if err != nil {
		log.Printf("ERROR: could not enqueue httpx task: %v", err)
	}
}

func EnqueueDirectoryScan(payload DirectoryScanPayload) {
	p, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: tidak dapat me-marshal payload direktori: %v", err)
		return
	}
	task := asynq.NewTask(TypeDirectoryScan, p)
	_, err = asynqClient.Enqueue(task)
	if err != nil {
		log.Printf("ERROR: tidak dapat menambahkan tugas direktori ke antrian: %v", err)
	}
}
