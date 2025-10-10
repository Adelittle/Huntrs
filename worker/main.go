package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

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

func sendUpdate(username, tool, updateType, message string) {
	update := map[string]string{"username": username, "tool": tool, "type": updateType, "message": message}
	payload, _ := json.Marshal(update)
	rdb.Publish(context.Background(), redisPubSubChannel, payload)
}

func notifyCancellation(username, tool, message string) {
	if message == "" {
		message = "Pemindaian dibatalkan oleh pengguna."
	}
	sendUpdate(username, tool, "scan_cancelled", message)
}

func downloadTempWordlist(source string) (string, func(), error) {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", func() {}, fmt.Errorf("invalid wordlist URL")
	}

	resp, err := http.Get(source)
	if err != nil {
		return "", func() {}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", func() {}, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	destDir := filepath.Join("scan_results", "wordlists")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", func() {}, err
	}

	tempFile, err := os.CreateTemp(destDir, "ffuf-url-wordlist-*.txt")
	if err != nil {
		return "", func() {}, err
	}
	defer tempFile.Close()

	if _, err := io.Copy(tempFile, resp.Body); err != nil {
		os.Remove(tempFile.Name())
		return "", func() {}, err
	}

	cleanup := func() {
		os.Remove(tempFile.Name())
	}

	return tempFile.Name(), cleanup, nil
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

	cancelled := false

	for _, target := range p.Targets {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
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
		if err := cmd.Start(); err != nil {
			sendUpdate(p.Username, "subdomain", "error", fmt.Sprintf("Tidak dapat memulai pemindaian untuk %s", target))
			return err
		}

		done := make(chan struct{})
		go func(command *exec.Cmd) {
			select {
			case <-ctx.Done():
				if command.Process != nil {
					command.Process.Kill()
				}
			case <-done:
			}
		}(cmd)

		scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
		for scanner.Scan() {
			if ctx.Err() != nil {
				cancelled = true
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
				break
			}
			line := scanner.Text()
			sendUpdate(p.Username, "subdomain", "data", line)
			if p.Tool == "assetfinder" && outputFile != nil && isPotentialSubdomain(line, target) {
				fmt.Fprintln(outputFile, strings.TrimSpace(line))
			}
		}

		close(done)

		if err := cmd.Wait(); err != nil && ctx.Err() == nil && !cancelled {
			log.Printf("Perintah selesai dengan error untuk target %s: %v", target, err)
			sendUpdate(p.Username, "subdomain", "error", fmt.Sprintf("Pemindaian untuk %s gagal.", target))
		}

		if cancelled {
			break
		}
	}

	if cancelled || ctx.Err() != nil {
		notifyCancellation(p.Username, "subdomain", "Pemindaian subdomain dibatalkan oleh pengguna.")
		return nil
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

	if ctx.Err() != nil {
		notifyCancellation(p.Username, "httpx", "HTTPx probe dibatalkan oleh pengguna.")
		return nil
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

	done := make(chan struct{})
	go func(command *exec.Cmd) {
		select {
		case <-ctx.Done():
			if command.Process != nil {
				command.Process.Kill()
			}
		case <-done:
		}
	}(cmd)

	scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
	for scanner.Scan() {
		if ctx.Err() != nil {
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			break
		}
		line := scanner.Text()
		sendUpdate(p.Username, "httpx", "data", line)
	}

	close(done)

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == nil {
			log.Printf("Httpx command finished with error: %v", err)
			sendUpdate(p.Username, "httpx", "error", "Httpx probe finished with an error.")
		}
	}

	if ctx.Err() != nil {
		notifyCancellation(p.Username, "httpx", "HTTPx probe dibatalkan oleh pengguna.")
		return nil
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

	if len(p.Targets) == 0 {
		sendUpdate(p.Username, "directory", "error", "Tidak ada target untuk dipindai")
		return fmt.Errorf("no targets provided")
	}
	log.Printf("Menerima tugas Directory scan untuk %d target", len(p.Targets))
	sendUpdate(p.Username, "directory", "info", fmt.Sprintf("Starting ffuf scan for %d target(s)", len(p.Targets)))

	cleanup := func() {}
	if p.WordlistOption == "url" && p.WordlistURL != "" {
		sendUpdate(p.Username, "directory", "info", fmt.Sprintf("Mengunduh wordlist dari %s", p.WordlistURL))
		downloadedPath, tempCleanup, err := downloadTempWordlist(p.WordlistURL)
		if err != nil {
			sendUpdate(p.Username, "directory", "error", fmt.Sprintf("Gagal mengunduh wordlist: %v", err))
			return err
		}
		p.Wordlist = downloadedPath
		cleanup = tempCleanup
		sendUpdate(p.Username, "directory", "info", "Wordlist siap digunakan untuk pemindaian")
	}
	defer cleanup()

	if p.Wordlist == "" {
		sendUpdate(p.Username, "directory", "error", "Wordlist tidak ditemukan atau kosong")
		return fmt.Errorf("wordlist kosong")
	}

	p.Wordlist = filepath.Clean(p.Wordlist)

	if p.UserAgentLabel != "" {
		sendUpdate(p.Username, "directory", "info", fmt.Sprintf("Menggunakan User-Agent preset: %s", p.UserAgentLabel))
	} else if p.UserAgent != "" {
		sendUpdate(p.Username, "directory", "info", fmt.Sprintf("Menggunakan User-Agent kustom: %s", p.UserAgent))
	}

	resultsDir := "scan_results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		sendUpdate(p.Username, "directory", "error", "Gagal membuat direktori hasil")
		return fmt.Errorf("tidak dapat membuat direktori hasil: %v", err)
	}

	var savedFiles []string
	cancelled := false

	for index, rawTarget := range p.Targets {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		target := strings.TrimSpace(rawTarget)
		if target == "" {
			continue
		}

		sendUpdate(p.Username, "directory", "info", fmt.Sprintf("Memulai pemindaian untuk %s", target))

		args := []string{"-u", target, "-w", p.Wordlist}
		if p.Method != "" {
			args = append(args, "-X", strings.ToUpper(p.Method))
		}
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
		if p.MatchWords != "" {
			args = append(args, "-mw", p.MatchWords)
		}
		if p.FilterWords != "" {
			args = append(args, "-fw", p.FilterWords)
		}
		if p.Timeout != "" {
			args = append(args, "-timeout", p.Timeout)
		}
		if p.Recursive {
			args = append(args, "-recursion")
			if p.RecursionDepth != "" {
				args = append(args, "-recursion-depth", p.RecursionDepth)
			}
		}
		for _, header := range p.Headers {
			trimmed := strings.TrimSpace(header)
			if trimmed != "" {
				args = append(args, "-H", trimmed)
			}
		}

		var outputFile *os.File
		var outputFilePath string
		if p.FileName != "" {
			actualName := buildDirectoryOutputName(p.FileName, target, index, len(p.Targets), p.OutputFormat)
			outputFilePath = filepath.Join(resultsDir, actualName)
			if p.OutputFormat == "html" {
				args = append(args, "-of", "html", "-o", outputFilePath)
			} else {
				args = append(args, "-o", outputFilePath)
				var err error
				outputFile, err = os.OpenFile(outputFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
				if err != nil {
					sendUpdate(p.Username, "directory", "error", "Gagal membuka file output")
					return fmt.Errorf("tidak dapat membuka file output: %v", err)
				}
				fmt.Fprintf(outputFile, "# ffuf scan results for %s\n", target)
			}
			savedFiles = append(savedFiles, actualName)
		}

		cmd := exec.Command("ffuf", args...)
		cmd.Env = append(os.Environ(), "TERM=dumb")

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			if outputFile != nil {
				outputFile.Close()
			}
			sendUpdate(p.Username, "directory", "error", "Gagal membuat stdout pipe untuk ffuf")
			return err
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			if outputFile != nil {
				outputFile.Close()
			}
			sendUpdate(p.Username, "directory", "error", "Gagal membuat stderr pipe untuk ffuf")
			return err
		}

		if err := cmd.Start(); err != nil {
			if outputFile != nil {
				outputFile.Close()
			}
			sendUpdate(p.Username, "directory", "error", "Tidak dapat memulai ffuf")
			return err
		}

		done := make(chan struct{})
		go func(command *exec.Cmd) {
			select {
			case <-ctx.Done():
				if command.Process != nil {
					command.Process.Kill()
				}
			case <-done:
			}
		}(cmd)

		scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			if ctx.Err() != nil {
				cancelled = true
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
				break
			}
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

		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			log.Printf("Scanner error for ffuf: %v", err)
		}

		close(done)

		if err := cmd.Wait(); err != nil {
			if ctx.Err() == nil && !cancelled {
				log.Printf("ffuf command finished with error: %v", err)
				sendUpdate(p.Username, "directory", "error", "ffuf selesai dengan error")
			}
		} else if !cancelled {
			sendUpdate(p.Username, "directory", "info", fmt.Sprintf("Pemindaian untuk %s selesai", target))
		}

		if outputFile != nil {
			outputFile.Close()
		}

		if cancelled {
			break
		}
	}

	if cancelled || ctx.Err() != nil {
		notifyCancellation(p.Username, "directory", "Directory fuzzing dibatalkan oleh pengguna.")
		return nil
	}

	successMessage := "\nDirectory scan completed."
	if len(savedFiles) > 0 {
		successMessage = fmt.Sprintf("\nDirectory scan completed. Results saved to: %s", strings.Join(savedFiles, ", "))
	}
	sendUpdate(p.Username, "directory", "info", successMessage)

	payload := map[string]interface{}{"tool": "directory"}
	if len(savedFiles) > 0 {
		payload["fileName"] = savedFiles[0]
		payload["fileNames"] = savedFiles
	} else if p.FileName != "" {
		payload["fileName"] = filepath.Base(p.FileName)
	}

	completionPayload, _ := json.Marshal(payload)
	sendUpdate(p.Username, "directory", "scan_completed", string(completionPayload))
	return nil
}

func buildDirectoryOutputName(baseName, target string, index, total int, format string) string {
	cleanBase := filepath.Base(baseName)
	ext := filepath.Ext(cleanBase)
	name := strings.TrimSuffix(cleanBase, ext)
	if name == "" {
		name = "directory-result"
	}

	if format == "html" {
		ext = ".html"
	} else {
		if strings.EqualFold(ext, ".html") || ext == "" {
			ext = ".txt"
		}
	}

	if total > 1 {
		fragment := sanitizeFileFragment(target)
		if fragment == "" {
			fragment = fmt.Sprintf("%d", index+1)
		}
		name = fmt.Sprintf("%s-%s", name, fragment)
	}

	return name + ext
}

func sanitizeFileFragment(value string) string {
	trimmed := strings.TrimSpace(value)
	if idx := strings.Index(trimmed, "://"); idx != -1 {
		trimmed = trimmed[idx+3:]
	}
	if idx := strings.Index(trimmed, "/"); idx != -1 {
		trimmed = trimmed[:idx]
	}

	var builder strings.Builder
	for _, r := range trimmed {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(unicode.ToLower(r))
		case r == '.' || r == '-' || r == '_':
			builder.WriteRune('-')
		}
	}

	result := builder.String()
	result = strings.Trim(result, "-")
	return result
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
