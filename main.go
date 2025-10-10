package main

import (
	"bugbounty/app/auth"
	"bugbounty/app/handlers"
	"bugbounty/app/state"
	"bugbounty/app/stats"
	"bugbounty/app/websocket"
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

const (
	redisAddr          = "127.0.0.1:6379"
	redisPubSubChannel = "scan_updates"
)

// listenForWorkerUpdates sekarang mengirimkan pembaruan ke semua perangkat pengguna.
func listenForWorkerUpdates() {
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	pubsub := rdb.Subscribe(context.Background(), redisPubSubChannel)
	defer pubsub.Close()
	ch := pubsub.Channel()
	log.Println("Mendengarkan update dari worker via Redis Pub/Sub...")

	for msg := range ch {
		var update map[string]string
		if err := json.Unmarshal([]byte(msg.Payload), &update); err == nil {
			username := update["username"] // Dapatkan username dari payload
			if username != "" {
				websocket.Manager.BroadcastToUser(username, []byte(msg.Payload))
			}

			// Jika pemindaian selesai, cari pengguna terkait dan hapus statusnya.
			if update["type"] == "scan_completed" {
				var completionData struct {
					Tool     string `json:"tool"`
					FileName string `json:"fileName"`
				}
				// Pesan sekarang adalah JSON, jadi kita perlu unmarshal
				if err := json.Unmarshal([]byte(update["message"]), &completionData); err == nil {
					// Cari pengguna yang statusnya cocok dengan file yang selesai
					if user, toolName, ok := state.FindUserByScanFile(completionData.FileName); ok {
						resolvedTool := completionData.Tool
						if resolvedTool == "" {
							resolvedTool = toolName
						}
						log.Printf("Scan '%s' for tool '%s' completed for user '%s'. Clearing state.", completionData.FileName, resolvedTool, user)
						state.ClearActiveScan(user, resolvedTool)
					} else if username != "" && completionData.Tool != "" {
						log.Printf("Scan for tool '%s' completed for user '%s'. Clearing state via fallback.", completionData.Tool, username)
						state.ClearActiveScan(username, completionData.Tool)
					}
				}
			} else if update["type"] == "scan_cancelled" {
				if username != "" && update["tool"] != "" {
					log.Printf("Scan for tool '%s' cancelled for user '%s'. Clearing state.", update["tool"], username)
					state.ClearActiveScan(username, update["tool"])
				}
			}
		}
	}
}

func main() {
	r := gin.Default()

	config := cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	r.Use(cors.New(config))

	go websocket.Manager.Run()
	go listenForWorkerUpdates()

	r.POST("/api/login", handlers.LoginHandler)
	r.GET("/ws", websocket.HandleConnection)

	protected := r.Group("/api")
	protected.Use(auth.Middleware())
	{
		protected.GET("/stats", stats.StatsHandler)
		protected.GET("/tools/status", handlers.ToolStatusHandler)
		protected.POST("/scan/subdomain", handlers.SubdomainScanHandler)
		protected.POST("/scan/httpx", handlers.HttpxScanHandler)
		protected.POST("/scan/directory", handlers.DirectoryScanHandler)
		protected.POST("/scan/stop", handlers.StopScanHandler)
		protected.POST("/results/load", handlers.LoadResultHandler)
		protected.POST("/results/extract", handlers.ExtractResultHandler)
		protected.GET("/user/status", handlers.UserStatusHandler)
		protected.POST("/user/clear-status", handlers.ClearUserStatusHandler)
	}

	log.Println("Backend server berjalan dan mendengarkan pada port :3000")
	if err := r.Run(":3000"); err != nil {
		log.Fatalf("Gagal menjalankan server: %v", err)
	}
}
