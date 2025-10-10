package stats

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// SystemStats mendefinisikan struktur data untuk statistik sistem.
type SystemStats struct {
	CPUPercent  float64 `json:"cpu"`
	RAMTotal    uint64  `json:"ram_total"`
	RAMUsed     uint64  `json:"ram_used"`
	RAMPercent  float64 `json:"ram_percent"`
	DiskTotal   uint64  `json:"disk_total"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskPercent float64 `json:"disk_percent"`
}

// StatsHandler adalah handler yang membaca data sistem dengan penanganan error yang lebih baik.
func StatsHandler(c *gin.Context) {
	// 1. Dapatkan Penggunaan CPU
	// cpu.Percent memerlukan durasi untuk mengukur penggunaan. time.Second adalah nilai yang umum.
	cpuPercentages, err := cpu.Percent(time.Second, false)
	if err != nil || len(cpuPercentages) == 0 {
		log.Printf("ERROR: Gagal mendapatkan statistik CPU: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Tidak dapat membaca statistik CPU"})
		return
	}

	// 2. Dapatkan Penggunaan Memori (RAM)
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("ERROR: Gagal mendapatkan statistik Memori: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Tidak dapat membaca statistik Memori"})
		return
	}

	// 3. Dapatkan Penggunaan Disk (dari partisi root "/")
	// Ini mengasumsikan partisi utama Anda adalah "/".
	diskStat, err := disk.Usage("/")
	if err != nil {
		log.Printf("ERROR: Gagal mendapatkan statistik Disk: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Tidak dapat membaca statistik Disk"})
		return
	}

	// Buat respons jika semua data berhasil didapatkan
	stats := SystemStats{
		CPUPercent:  cpuPercentages[0],
		RAMTotal:    vmStat.Total,
		RAMUsed:     vmStat.Used,
		RAMPercent:  vmStat.UsedPercent,
		DiskTotal:   diskStat.Total,
		DiskUsed:    diskStat.Used,
		DiskPercent: diskStat.UsedPercent,
	}

	c.JSON(http.StatusOK, stats)
}

