package state

import "sync"

// ScanInfo menyimpan metadata pemindaian aktif untuk sebuah tool.
type ScanInfo struct {
	FileName string `json:"fileName,omitempty"`
	Status   string `json:"status"`
	TaskID   string `json:"-"`
	Queue    string `json:"-"`
}

// activeScans adalah peta thread-safe yang menyimpan informasi pemindaian per pengguna dan per tool.
var activeScans = make(map[string]map[string]*ScanInfo)
var mutex = &sync.Mutex{}

func ensureUserTool(username, tool string) *ScanInfo {
	if _, ok := activeScans[username]; !ok {
		activeScans[username] = make(map[string]*ScanInfo)
	}
	if info, ok := activeScans[username][tool]; ok {
		return info
	}
	info := &ScanInfo{Status: "idle"}
	activeScans[username][tool] = info
	return info
}

// SetActiveScan mencatat bahwa seorang pengguna telah memulai pemindaian baru untuk tool tertentu.
func SetActiveScan(username, tool string, info ScanInfo) {
	mutex.Lock()
	defer mutex.Unlock()
	existing := ensureUserTool(username, tool)
	existing.FileName = info.FileName
	existing.Status = info.Status
	existing.TaskID = info.TaskID
	existing.Queue = info.Queue
}

// UpdateScanStatus memperbarui status pemindaian tanpa mengubah metadata lain.
func UpdateScanStatus(username, tool, status string) {
	mutex.Lock()
	defer mutex.Unlock()
	existing := ensureUserTool(username, tool)
	existing.Status = status
	if status == "idle" {
		existing.FileName = ""
		existing.TaskID = ""
		existing.Queue = ""
	}
}

// GetScanInfo mengambil informasi pemindaian untuk tool tertentu.
func GetScanInfo(username, tool string) (ScanInfo, bool) {
	mutex.Lock()
	defer mutex.Unlock()
	if userScans, ok := activeScans[username]; ok {
		if info, ok := userScans[tool]; ok && info != nil {
			return *info, true
		}
	}
	return ScanInfo{}, false
}

// GetUserStatus mengambil seluruh peta pemindaian aktif untuk seorang pengguna.
func GetUserStatus(username string) (map[string]ScanInfo, bool) {
	mutex.Lock()
	defer mutex.Unlock()
	userScans, ok := activeScans[username]
	if !ok {
		return nil, false
	}
	scanCopy := make(map[string]ScanInfo)
	for tool, info := range userScans {
		if info == nil {
			continue
		}
		scanCopy[tool] = *info
	}
	return scanCopy, true
}

// ClearActiveScan menyetel status tool menjadi idle dan menghapus metadata terkait.
func ClearActiveScan(username, tool string) {
	mutex.Lock()
	defer mutex.Unlock()
	if _, ok := activeScans[username]; !ok {
		activeScans[username] = make(map[string]*ScanInfo)
	}
	info, ok := activeScans[username][tool]
	if !ok || info == nil {
		info = &ScanInfo{}
		activeScans[username][tool] = info
	}
	info.Status = "idle"
	info.FileName = ""
	info.TaskID = ""
	info.Queue = ""

	// Jika semua tool pengguna berada pada status idle dan tanpa metadata, bersihkan entri pengguna.
	empty := true
	for _, scan := range activeScans[username] {
		if scan != nil && (scan.Status != "idle" || scan.FileName != "" || scan.TaskID != "") {
			empty = false
			break
		}
	}
	if empty {
		delete(activeScans, username)
	}
}

// FindUserByScanFile mencari pengguna dan tool berdasarkan nama file pemindaian.
func FindUserByScanFile(fileName string) (string, string, bool) {
	mutex.Lock()
	defer mutex.Unlock()
	for user, tools := range activeScans {
		for tool, info := range tools {
			if info != nil && info.FileName == fileName {
				return user, tool, true
			}
		}
	}
	return "", "", false
}
