package state

import "sync"

// activeScans adalah peta thread-safe yang menyimpan nama file pemindaian aktif per pengguna per tool.
// Struktur: map[username] -> map[toolName] -> fileName
var activeScans = make(map[string]map[string]string)
var mutex = &sync.Mutex{}

// SetActiveScan mencatat bahwa seorang pengguna telah memulai pemindaian baru untuk tool tertentu.
func SetActiveScan(username, tool, fileName string) {
	mutex.Lock()
	defer mutex.Unlock()
	if _, ok := activeScans[username]; !ok {
		activeScans[username] = make(map[string]string)
	}
	activeScans[username][tool] = fileName
}

// GetUserStatus mengambil seluruh peta pemindaian aktif untuk seorang pengguna.
func GetUserStatus(username string) (map[string]string, bool) {
	mutex.Lock()
	defer mutex.Unlock()
	userScans, ok := activeScans[username]
	// Buat salinan untuk menghindari race condition jika dipanggil dari luar
	if ok {
		scanCopy := make(map[string]string)
		for tool, file := range userScans {
			scanCopy[tool] = file
		}
		return scanCopy, true
	}
	return nil, false
}

// ClearActiveScan menghapus catatan pemindaian aktif untuk tool tertentu dari seorang pengguna.
func ClearActiveScan(username, tool string) {
	mutex.Lock()
	defer mutex.Unlock()
	if userScans, ok := activeScans[username]; ok {
		delete(userScans, tool)
		if len(userScans) == 0 {
			delete(activeScans, username)
		}
	}
}

// --- FUNGSI BARU ---
// FindUserByScanFile mencari pengguna yang menjalankan pemindaian dengan nama file tertentu.
// Ini diperlukan agar kita bisa menghapus status saat pemindaian selesai.
func FindUserByScanFile(fileName string) (string, bool) {
	mutex.Lock()
	defer mutex.Unlock()
	for user, tools := range activeScans {
		for _, file := range tools {
			if file == fileName {
				return user, true
			}
		}
	}
	return "", false
}

