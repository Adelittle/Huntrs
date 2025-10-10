package websocket

import (
	"bugbounty/app/auth"
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Izinkan semua koneksi untuk development
		return true
	},
}

// Client merepresentasikan satu koneksi WebSocket dari satu perangkat.
type Client struct {
	Hub      *Hub
	Conn     *websocket.Conn
	Send     chan []byte
	Username string // Setiap koneksi sekarang terikat pada seorang pengguna
}

// writePump memompa pesan dari hub ke koneksi WebSocket.
func (c *Client) writePump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()
	for {
		message, ok := <-c.Send
		if !ok {
			// Hub menutup channel ini.
			c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}
		c.Conn.WriteMessage(websocket.TextMessage, message)
	}
}

// Hub mengelola semua client dan menyiarkan pesan.
type Hub struct {
	// Kunci peta adalah username. Nilainya adalah peta lain
	// yang berisi semua koneksi aktif untuk pengguna tersebut.
	Clients    map[string]map[*Client]bool
	Broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.Mutex
}

func NewHub() *Hub {
	return &Hub{
		Clients:    make(map[string]map[*Client]bool),
		Broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run menjalankan Hub di goroutine terpisah.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			// Jika ini koneksi pertama untuk pengguna ini, buat entri baru.
			if _, ok := h.Clients[client.Username]; !ok {
				h.Clients[client.Username] = make(map[*Client]bool)
			}
			h.Clients[client.Username][client] = true
			log.Printf("Client terdaftar untuk pengguna: %s", client.Username)
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			if clients, ok := h.Clients[client.Username]; ok {
				if _, ok := clients[client]; ok {
					delete(clients, client)
					close(client.Send)
					// Jika tidak ada lagi koneksi untuk pengguna ini, hapus entri pengguna.
					if len(clients) == 0 {
						delete(h.Clients, client.Username)
					}
					log.Printf("Client tidak terdaftar untuk pengguna: %s", client.Username)
				}
			}
			h.mu.Unlock()
		}
	}
}

// GetUserClients mengembalikan semua koneksi aktif untuk seorang pengguna.
func (h *Hub) GetUserClients(username string) []*Client {
	h.mu.Lock()
	defer h.mu.Unlock()
	var userClients []*Client
	if clients, ok := h.Clients[username]; ok {
		for client := range clients {
			userClients = append(userClients, client)
		}
	}
	return userClients
}

func safeSendToClient(client *Client, message []byte, block bool) bool {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered from websocket send for user %s: %v", client.Username, r)
		}
	}()
	if block {
		client.Send <- message
		return true
	}
	select {
	case client.Send <- message:
		return true
	default:
		return false
	}
}

func (h *Hub) BroadcastToUser(username string, message []byte) {
	h.mu.Lock()
	clientsMap, ok := h.Clients[username]
	var clients []*Client
	if ok {
		for client := range clientsMap {
			clients = append(clients, client)
		}
	}
	h.mu.Unlock()

	if len(clients) == 0 {
		return
	}

	for _, client := range clients {
		msgCopy := append([]byte(nil), message...)
		if !safeSendToClient(client, msgCopy, false) {
			go func(c *Client, payload []byte) {
				safeSendToClient(c, payload, true)
			}(client, msgCopy)
		}
	}
}

var Manager = NewHub()

// HandleConnection menangani permintaan upgrade ke WebSocket.
func HandleConnection(c *gin.Context) {
	// Ambil token dari query parameter
	tokenString := c.Query("token")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak ditemukan"})
		return
	}

	// Validasi token untuk mendapatkan username
	claims := &auth.Claims{}
	_, err := auth.ValidateToken(tokenString, claims)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
		return
	}

	// Upgrade koneksi HTTP ke WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println(err)
		return
	}

	// Buat client baru dengan username yang sudah divalidasi
	client := &Client{Hub: Manager, Conn: conn, Send: make(chan []byte, 256), Username: claims.Username}
	Manager.register <- client

	// Jalankan writePump di goroutine terpisah untuk setiap client
	go client.writePump()
}
