package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/hibiken/asynq"
)

const (
	redisAddr          = "127.0.0.1:6379"
	redisPubSubChannel = "scan_updates"
)

var rdb = redis.NewClient(&redis.Options{Addr: redisAddr})

type SubdomainScanPayload struct {
	Targets  []string `json:"targets"`
	Tool     string   `json:"tool"`
	FileName string   `json:"fileName"`
	Username string   `json:"username"`
}

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

func sendUpdate(username, tool, updateType, message string) {
	update := map[string]string{"username": username, "tool": tool, "type": updateType, "message": message}
	payload, _ := json.Marshal(update)
	rdb.Publish(context.Background(), redisPubSubChannel, payload)
}

func getSublist3rCommand() []string {
	if _, err := exec.LookPath("sublist3r"); err == nil {
		return []string{"sublist3r"}
	}
	scriptPath := "/root/Sublist3r/sublist3r.py"
	if _, err := os.Stat(scriptPath); err == nil {
		return []string{"python3", scriptPath}
	}
	return []string{"sublist3r"}
}

func isPotentialSubdomain(line, target string) bool {
	trimmedLine := strings.TrimSpace(line)
	return !strings.Contains(trimmedLine, " ") && strings.HasSuffix(trimmedLine, target)
}

func handleSubdomainScanTask(ctx context.Context, t *asynq.Task) error {
	var p SubdomainScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("tidak dapat membuka marshal payload: %v", err)
	}
	log.Printf("Menerima tugas subdomain: Tool=%s, User=%s", p.Tool, p.Username)
	sendUpdate(p.Username, "subdomain", "info", fmt.Sprintf("Memulai pemindaian %s untuk %d target...", p.Tool, len(p.Targets)))

	resultsDir := "scan_results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		sendUpdate(p.Username, "subdomain", "error", "Gagal membuat direktori hasil")
		return fmt.Errorf("tidak dapat membuat direktori hasil: %v", err)
	}

	var outputFile *os.File
	var err error
	if p.FileName != "" {
		safeFileName := filepath.Base(p.FileName)
		filePath := filepath.Join(resultsDir, safeFileName)
		outputFile, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			sendUpdate(p.Username, "subdomain", "error", "Gagal membuka file output")
			return fmt.Errorf("tidak dapat membuka file output: %v", err)
		}
		defer outputFile.Close()
	}

	for _, target := range p.Targets {
		if target == "" {
			continue
		}
		infoMessage := fmt.Sprintf("\n--- Memindai target: %s ---", target)
		sendUpdate(p.Username, "subdomain", "info", infoMessage)

		var cmd *exec.Cmd
		switch p.Tool {
		case "amass":
			args := []string{"enum", "-d", target}
			if outputFile != nil {
				args = append(args, "-o", outputFile.Name())
			}
			cmd = exec.Command("amass", args...)
		case "assetfinder":
			cmd = exec.Command("assetfinder", "-subs-only", target)
		case "sublist3r":
			sublist3rCmd := getSublist3rCommand()
			args := []string{"-d", target}
			if outputFile != nil {
				args = append(args, "-o", outputFile.Name())
			}
			fullCommand := append(sublist3rCmd, args...)
			cmd = exec.Command(fullCommand[0], fullCommand[1:]...)
		case "subfinder":
			args := []string{"-d", target}
			if outputFile != nil {
				args = append(args, "-o", outputFile.Name())
			}
			cmd = exec.Command("subfinder", args...)
		default:
			sendUpdate(p.Username, "subdomain", "error", "Tool yang dipilih tidak dikenal")
			return fmt.Errorf("tool tidak dikenal: %s", p.Tool)
		}

		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		cmd.Start()

		scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
		for scanner.Scan() {
			line := scanner.Text()
			sendUpdate(p.Username, "subdomain", "data", line)
			if p.Tool == "assetfinder" && outputFile != nil && isPotentialSubdomain(line, target) {
				fmt.Fprintln(outputFile, strings.TrimSpace(line))
			}
		}

		if err := cmd.Wait(); err != nil {
			log.Printf("Perintah selesai dengan error untuk target %s: %v", target, err)
			sendUpdate(p.Username, "subdomain", "error", fmt.Sprintf("Pemindaian untuk %s gagal.", target))
		}
	}

	successMsg := fmt.Sprintf("\nPemindaian selesai. Hasil disimpan ke %s", p.FileName)
	sendUpdate(p.Username, "subdomain", "info", successMsg)
	completionPayload, _ := json.Marshal(map[string]string{"tool": "subdomain", "fileName": p.FileName})
	sendUpdate(p.Username, "subdomain", "scan_completed", string(completionPayload))
	return nil
}

// handleHttpxScanTask sekarang menghapus flag -no-stdin.
func handleHttpxScanTask(ctx context.Context, t *asynq.Task) error {
	var p HttpxScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("could not unmarshal httpx payload: %v", err)
	}
	log.Printf("Menerima tugas Httpx: Targets=%d, User=%s", len(p.Targets), p.Username)
	sendUpdate(p.Username, "httpx", "info", fmt.Sprintf("Starting HTTPx probe for %d targets...", len(p.Targets)))

	resultsDir := "scan_results"
	os.MkdirAll(resultsDir, 0755)

	args := []string{}
	for _, opt := range p.Options {
		args = append(args, "-"+opt)
	}
	if p.Threads != "" {
		args = append(args, "-threads", p.Threads)
	}
	if p.Timeout != "" {
		args = append(args, "-timeout", p.Timeout)
	}
	if p.NoColor {
		args = append(args, "-no-color")
	}
	if p.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	if p.Method != "" {
		args = append(args, "-x", p.Method)
	}
	if p.FilterStatusCodes != "" {
		args = append(args, "-mc", p.FilterStatusCodes)
	}

	if p.FileName != "" {
		filePath := filepath.Join(resultsDir, filepath.Base(p.FileName))
		args = append(args, "-o", filePath)
	}

	cmd := exec.Command("httpx", args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		sendUpdate(p.Username, "httpx", "error", "Failed to create stdin pipe for httpx")
		return err
	}
	go func() {
		defer stdin.Close()
		for _, target := range p.Targets {
			io.WriteString(stdin, target+"\n")
		}
	}()

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		sendUpdate(p.Username, "httpx", "error", "Failed to start httpx command")
		return err
	}

	scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
	for scanner.Scan() {
		line := scanner.Text()
		sendUpdate(p.Username, "httpx", "data", line)
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("Httpx command finished with error: %v", err)
		sendUpdate(p.Username, "httpx", "error", "Httpx probe finished with an error.")
	}

	successMsg := "\nHTTPx probe completed."
	if p.FileName != "" {
		successMsg = fmt.Sprintf("\nHTTPx probe completed. Results saved to %s", p.FileName)
	}
	sendUpdate(p.Username, "httpx", "info", successMsg)
	completionPayload, _ := json.Marshal(map[string]string{"tool": "httpx", "fileName": p.FileName})
	sendUpdate(p.Username, "httpx", "scan_completed", string(completionPayload))
	return nil
}

func handleDirectoryScanTask(ctx context.Context, t *asynq.Task) error {
	var p DirectoryScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("could not unmarshal directory payload: %v", err)
	}

	log.Printf("Menerima tugas Directory scan untuk %s", p.Target)
	sendUpdate(p.Username, "directory", "info", fmt.Sprintf("Starting ffuf scan against %s", p.Target))

	if p.Wordlist == "" {
		sendUpdate(p.Username, "directory", "error", "Wordlist tidak ditemukan atau kosong")
		return fmt.Errorf("wordlist kosong")
	}

	resultsDir := "scan_results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		sendUpdate(p.Username, "directory", "error", "Gagal membuat direktori hasil")
		return fmt.Errorf("tidak dapat membuat direktori hasil: %v", err)
	}

	var outputFile *os.File
	var err error
	if p.FileName != "" {
		filePath := filepath.Join(resultsDir, filepath.Base(p.FileName))
		outputFile, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			sendUpdate(p.Username, "directory", "error", "Gagal membuka file output")
			return fmt.Errorf("tidak dapat membuka file output: %v", err)
		}
		defer outputFile.Close()
		fmt.Fprintf(outputFile, "# ffuf scan results for %s\n", p.Target)
	}

	args := []string{"-u", p.Target, "-w", p.Wordlist}
	if p.Extensions != "" {
		args = append(args, "-e", p.Extensions)
	}
	if p.Threads != "" {
		args = append(args, "-t", p.Threads)
	}
	if p.Delay != "" {
		args = append(args, "-p", p.Delay)
	}
	if p.MatchCodes != "" {
		args = append(args, "-mc", p.MatchCodes)
	}
	if p.Recursive {
		args = append(args, "-recursion")
	}
	for _, header := range p.Headers {
		trimmed := strings.TrimSpace(header)
		if trimmed != "" {
			args = append(args, "-H", trimmed)
		}
	}

	cmd := exec.Command("ffuf", args...)
	cmd.Env = append(os.Environ(), "TERM=dumb")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sendUpdate(p.Username, "directory", "error", "Gagal membuat stdout pipe untuk ffuf")
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		sendUpdate(p.Username, "directory", "error", "Gagal membuat stderr pipe untuk ffuf")
		return err
	}

	if err := cmd.Start(); err != nil {
		sendUpdate(p.Username, "directory", "error", "Tidak dapat memulai ffuf")
		return err
	}

	scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		cleaned := strings.ReplaceAll(line, "\r", "")
		if strings.TrimSpace(cleaned) == "" {
			continue
		}
		sendUpdate(p.Username, "directory", "data", cleaned)
		if outputFile != nil {
			fmt.Fprintln(outputFile, cleaned)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error for ffuf: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("ffuf command finished with error: %v", err)
		sendUpdate(p.Username, "directory", "error", "ffuf selesai dengan error")
	}

	successMessage := "\nDirectory scan completed."
	if p.FileName != "" {
		successMessage = fmt.Sprintf("\nDirectory scan completed. Results saved to %s", p.FileName)
	}
	sendUpdate(p.Username, "directory", "info", successMessage)

	completionPayload, _ := json.Marshal(map[string]string{"tool": "directory", "fileName": p.FileName})
	sendUpdate(p.Username, "directory", "scan_completed", string(completionPayload))
	return nil
}

func main() {
	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: redisAddr},
		asynq.Config{Concurrency: 10},
	)
	mux := asynq.NewServeMux()
	mux.HandleFunc("scan:subdomain", handleSubdomainScanTask)
	mux.HandleFunc("scan:httpx", handleHttpxScanTask)
	mux.HandleFunc("scan:directory", handleDirectoryScanTask)

	log.Println("Worker berjalan dan siap menerima tugas...")
	if err := srv.Run(mux); err != nil {
		log.Fatalf("tidak dapat menjalankan server: %v", err)
	}
}
