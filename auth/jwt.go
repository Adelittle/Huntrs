package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Kunci rahasia untuk menandatangani token. Di aplikasi produksi, ini harus
// diambil dari environment variable dan jauh lebih kompleks.
var JwtKey = []byte("kunci_rahasia_yang_sangat_aman_dan_panjang")

// Claims adalah struktur data yang akan kita simpan di dalam token.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateToken membuat token JWT baru untuk pengguna yang diberikan.
func GenerateToken(username string) (string, error) {
	// Menentukan waktu kedaluwarsa token (misalnya, 24 jam)
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Membuat token dengan claims dan metode penandatanganan HS256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Menandatangani token dengan kunci rahasia kita
	return token.SignedString(JwtKey)
}

// --- FUNGSI BARU ---
// ValidateToken mem-parse dan memvalidasi token JWT, mengembalikan claims jika valid.
func ValidateToken(tokenString string, claims *Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})
}

// Middleware adalah middleware Gin untuk memverifikasi token JWT.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Mendapatkan header Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Header otorisasi tidak ditemukan"})
			c.Abort()
			return
		}

		// Memeriksa format "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Format header otorisasi salah"})
			c.Abort()
			return
		}
		tokenString := parts[1]

		claims := &Claims{}
		// Menggunakan fungsi ValidateToken yang baru
		token, err := ValidateToken(tokenString, claims)

		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token telah kedaluwarsa"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
			}
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
			c.Abort()
			return
		}

		// Menyimpan username di konteks Gin untuk digunakan oleh handler selanjutnya
		c.Set("username", claims.Username)
		c.Next()
	}
}

