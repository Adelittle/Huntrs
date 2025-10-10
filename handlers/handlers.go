package handlers

import (
	"bugbounty/app/auth"
	"bugbounty/app/state"
	"bugbounty/app/tasks"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// LoginPayload mendefinisikan struktur data yang diharapkan dari body request login.
type LoginPayload struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginHandler memvalidasi kredensial dan membuat token JWT.
func LoginHandler(c *gin.Context) {
	var payload LoginPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Payload tidak valid: " + err.Error()})
		return
	}

	if payload.Username == "nakanosec-user" && payload.Password == "nakanosec-password" {
		token, err := auth.GenerateToken(payload.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
	}
}

// SubdomainScanHandler sekarang mencatat status pemindaian di sisi server.
func SubdomainScanHandler(c *gin.Context) {
	username, _ := c.Get("username")
	mode := c.PostForm("mode")
	tool := c.PostForm("tool")
	fileName := c.PostForm("fileName")

	var targets []string

	switch mode {
	case "single":
		target := c.PostForm("target")
		if target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Target diperlukan untuk mode single"})
			return
		}
		targets = []string{target}
	case "bulk":
		bulkTargets := c.PostForm("targets")
		targets = strings.Split(strings.ReplaceAll(bulkTargets, "\r\n", "\n"), "\n")
	case "file":
		file, err := c.FormFile("targetFile")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File diperlukan untuk mode file"})
			return
		}
		fileContent, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Tidak dapat membuka file"})
			return
		}
		defer fileContent.Close()
		bytes, err := ioutil.ReadAll(fileContent)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Tidak dapat membaca konten file"})
			return
		}
		targets = strings.Split(strings.ReplaceAll(string(bytes), "\r\n", "\n"), "\n")
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Mode scan tidak valid"})
		return
	}

	var cleanedTargets []string
	for _, t := range targets {
		if strings.TrimSpace(t) != "" {
			cleanedTargets = append(cleanedTargets, strings.TrimSpace(t))
		}
	}

	if len(cleanedTargets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tidak ada target yang valid"})
		return
	}

	payload := tasks.SubdomainScanPayload{
		Targets:  cleanedTargets,
		Tool:     tool,
		FileName: fileName,
		Username: username.(string),
	}

	tasks.EnqueueSubdomainScan(payload)
	// Catat pemindaian aktif untuk tool "subdomain".
	state.SetActiveScan(username.(string), "subdomain", fileName)

	c.JSON(http.StatusOK, gin.H{"message": "Tugas subdomain scan telah ditambahkan ke antrian"})
}

// HttpxScanHandler juga sekarang menggunakan state manager.
func HttpxScanHandler(c *gin.Context) {
	username, _ := c.Get("username")
	mode := c.PostForm("mode")
	fileName := c.PostForm("fileName")
	threads := c.PostForm("threads")
	timeout := c.PostForm("timeout")
	options := c.PostFormArray("options")
	noColor := c.PostForm("noColor") == "true"
	followRedirects := c.PostForm("followRedirects") == "true"
	method := c.PostForm("method")
	filterStatusCodes := c.PostForm("filterStatusCodes")

	var targets []string
	switch mode {
	case "single":
		target := c.PostForm("target")
		if target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Target is required for single mode"})
			return
		}
		targets = []string{target}
	case "bulk":
		bulkTargets := c.PostForm("targets")
		targets = strings.Split(strings.ReplaceAll(bulkTargets, "\r\n", "\n"), "\n")
	case "file":
		file, err := c.FormFile("targetFile")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File is required for file mode"})
			return
		}
		fileContent, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not open file"})
			return
		}
		defer fileContent.Close()
		bytes, err := ioutil.ReadAll(fileContent)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read file content"})
			return
		}
		targets = strings.Split(strings.ReplaceAll(string(bytes), "\r\n", "\n"), "\n")
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan mode"})
		return
	}

	var cleanedTargets []string
	for _, t := range targets {
		if strings.TrimSpace(t) != "" {
			cleanedTargets = append(cleanedTargets, strings.TrimSpace(t))
		}
	}
	if len(cleanedTargets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid targets provided"})
		return
	}

	payload := tasks.HttpxScanPayload{
		Targets:           cleanedTargets,
		FileName:          fileName,
		Username:          username.(string),
		Threads:           threads,
		Timeout:           timeout,
		Options:           options,
		NoColor:           noColor,
		FollowRedirects:   followRedirects,
		Method:            method,
		FilterStatusCodes: filterStatusCodes,
	}

	tasks.EnqueueHttpxScan(payload)
	// Catat pemindaian aktif untuk tool "httpx".
	state.SetActiveScan(username.(string), "httpx", fileName)

	c.JSON(http.StatusOK, gin.H{"message": "Httpx probe task has been added to the queue"})
}

func DirectoryScanHandler(c *gin.Context) {
	username, _ := c.Get("username")
	mode := c.PostForm("mode")
	extensions := strings.TrimSpace(c.PostForm("extensions"))
	threads := strings.TrimSpace(c.PostForm("threads"))
	delay := strings.TrimSpace(c.PostForm("delay"))
	matchCodes := strings.TrimSpace(c.PostForm("matchCodes"))
	matchWords := strings.TrimSpace(c.PostForm("matchWords"))
	filterWords := strings.TrimSpace(c.PostForm("filterWords"))
	timeout := strings.TrimSpace(c.PostForm("timeout"))
	recursionDepth := strings.TrimSpace(c.PostForm("recursionDepth"))
	recursive := c.PostForm("recursive") == "true"
	method := strings.ToUpper(strings.TrimSpace(c.PostForm("method")))
	if method == "" {
		method = "GET"
	}
	if method != "GET" && method != "POST" && method != "PUT" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Metode permintaan tidak valid"})
		return
	}

	outputFormat := strings.TrimSpace(c.PostForm("outputFormat"))
	if outputFormat == "" {
		outputFormat = "text"
	}
	if outputFormat != "text" && outputFormat != "html" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Format output tidak dikenal"})
		return
	}

	wordlistOption := c.PostForm("wordlistOption")
	wordlist := strings.TrimSpace(c.PostForm("wordlist"))
	wordlistURL := strings.TrimSpace(c.PostForm("wordlistUrl"))
	userAgent := strings.TrimSpace(c.PostForm("userAgent"))
	userAgentLabel := strings.TrimSpace(c.PostForm("userAgentLabel"))

	rawHeaders := c.PostFormArray("headers[]")
	if len(rawHeaders) == 0 {
		rawHeaders = c.PostFormArray("headers")
	}
	var headers []string
	for _, h := range rawHeaders {
		trimmed := strings.TrimSpace(h)
		if trimmed != "" {
			headers = append(headers, trimmed)
		}
	}
	if userAgent != "" {
		headers = append(headers, fmt.Sprintf("User-Agent: %s", userAgent))
	}

	var targets []string
	switch mode {
	case "single":
		target := strings.TrimSpace(c.PostForm("target"))
		if target != "" {
			targets = append(targets, target)
		}
	case "bulk":
		bulkTargets := strings.ReplaceAll(c.PostForm("targets"), "\r\n", "\n")
		for _, t := range strings.Split(bulkTargets, "\n") {
			if strings.TrimSpace(t) != "" {
				targets = append(targets, strings.TrimSpace(t))
			}
		}
	case "file":
		file, err := c.FormFile("targetFile")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File target diperlukan"})
			return
		}
		fileContent, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Tidak dapat membuka file target"})
			return
		}
		defer fileContent.Close()
		bytes, err := ioutil.ReadAll(fileContent)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Tidak dapat membaca konten file target"})
			return
		}
		lines := strings.ReplaceAll(string(bytes), "\r\n", "\n")
		for _, t := range strings.Split(lines, "\n") {
			if strings.TrimSpace(t) != "" {
				targets = append(targets, strings.TrimSpace(t))
			}
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Mode target tidak valid"})
		return
	}

	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Minimal satu target diperlukan"})
		return
	}

	if wordlistOption == "url" {
		if wordlistURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "URL wordlist diperlukan"})
			return
		}
		downloadedPath, err := downloadWordlistFromURL(wordlistURL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Gagal mengunduh wordlist: %v", err)})
			return
		}
		wordlist = downloadedPath
	}

	if wordlist == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Wordlist diperlukan"})
		return
	}

	fileName := strings.TrimSpace(c.PostForm("fileName"))
	if fileName == "" {
		suffix := ".txt"
		if outputFormat == "html" {
			suffix = ".html"
		}
		fileName = fmt.Sprintf("directory-result-%d%s", time.Now().Unix(), suffix)
	} else {
		baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
		if outputFormat == "html" {
			fileName = baseName + ".html"
		} else if filepath.Ext(fileName) == "" {
			fileName = baseName + ".txt"
		}
	}

	payload := tasks.DirectoryScanPayload{
		Targets:        targets,
		TargetMode:     mode,
		Wordlist:       wordlist,
		WordlistOption: wordlistOption,
		WordlistURL:    wordlistURL,
		FileName:       fileName,
		Username:       username.(string),
		Extensions:     extensions,
		Threads:        threads,
		Delay:          delay,
		MatchCodes:     matchCodes,
		MatchWords:     matchWords,
		FilterWords:    filterWords,
		Timeout:        timeout,
		Recursive:      recursive,
		RecursionDepth: recursionDepth,
		Headers:        headers,
		Method:         method,
		OutputFormat:   outputFormat,
		UserAgent:      userAgent,
		UserAgentLabel: userAgentLabel,
	}

	tasks.EnqueueDirectoryScan(payload)
	state.SetActiveScan(username.(string), "directory", fileName)

	c.JSON(http.StatusOK, gin.H{"message": "Tugas directory scan telah ditambahkan ke antrian", "fileName": fileName})
}

func downloadWordlistFromURL(source string) (string, error) {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("URL tidak valid")
	}

	resp, err := http.Get(source)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gagal mengunduh wordlist, status %d", resp.StatusCode)
	}

	destDir := filepath.Join("scan_results", "wordlists")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", err
	}

	candidate := path.Base(parsed.Path)
	if candidate == "" || candidate == "." || candidate == ".." {
		candidate = fmt.Sprintf("wordlist-%d.txt", time.Now().Unix())
	}

	if filepath.Ext(candidate) == "" {
		candidate = candidate + ".txt"
	}

	safeName := filepath.Base(candidate)
	base := strings.TrimSuffix(safeName, filepath.Ext(safeName))
	ext := filepath.Ext(safeName)
	filePath := filepath.Join(destDir, safeName)
	if _, err := os.Stat(filePath); err == nil {
		filePath = filepath.Join(destDir, fmt.Sprintf("%s-%d%s", base, time.Now().Unix(), ext))
	}

	out, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", err
	}

	return filePath, nil
}

type ToolStatus struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
}

func isToolInstalled(name string, alternativePath string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	if alternativePath != "" {
		if _, err := os.Stat(alternativePath); err == nil {
			return true
		}
	}
	return false
}

func ToolStatusHandler(c *gin.Context) {
	tools := map[string]string{
		"amass":       "",
		"assetfinder": "",
		"sublist3r":   "/root/Sublist3r/sublist3r.py",
		"subfinder":   "",
		"httpx":       "",
		"ffuf":        "",
	}
	var statuses []ToolStatus
	for name, altPath := range tools {
		statuses = append(statuses, ToolStatus{Name: name, Installed: isToolInstalled(name, altPath)})
	}
	c.JSON(http.StatusOK, statuses)
}

func LoadResultHandler(c *gin.Context) {
	var body struct {
		FileName string `json:"fileName" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nama file diperlukan"})
		return
	}
	resultsDir := "scan_results"
	cleanFileName := filepath.Base(body.FileName)
	fullPath := filepath.Join(resultsDir, cleanFileName)
	log.Printf("Mencoba memuat file hasil: %s", fullPath)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "File tidak ditemukan"})
		return
	}
	content, err := ioutil.ReadFile(fullPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Tidak dapat membaca file"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"content": string(content)})
}

func ExtractResultHandler(c *gin.Context) {
	var body struct {
		FileName string `json:"fileName" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nama file diperlukan"})
		return
	}
	resultsDir := "scan_results"
	cleanFileName := filepath.Base(body.FileName)
	fullPath := filepath.Join(resultsDir, cleanFileName)
	log.Printf("Mencoba mengekstrak file hasil: %s", fullPath)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "File tidak ditemukan"})
		return
	}
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+cleanFileName)
	c.Header("Content-Type", "text/plain")
	c.File(fullPath)
}

// UserStatusHandler sekarang mengembalikan peta pemindaian aktif.
func UserStatusHandler(c *gin.Context) {
	username, _ := c.Get("username")
	if activeScans, ok := state.GetUserStatus(username.(string)); ok {
		c.JSON(http.StatusOK, gin.H{"activeScans": activeScans})
	} else {
		c.JSON(http.StatusOK, gin.H{"activeScans": nil})
	}
}

// ClearUserStatusHandler sekarang menerima nama tool yang akan dihapus.
func ClearUserStatusHandler(c *gin.Context) {
	var body struct {
		Tool string `json:"tool" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nama tool diperlukan"})
		return
	}
	username, _ := c.Get("username")
	state.ClearActiveScan(username.(string), body.Tool)
	c.JSON(http.StatusOK, gin.H{"message": "Status berhasil dihapus"})
}
