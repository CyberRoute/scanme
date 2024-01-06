package util

import (
	"math/rand"
	"time"
)

// generateRandomPort generates a random TCP port number.
func generateRandomPort() uint16 {
	rand.Seed(time.Now().UnixNano())
	return uint16(rand.Intn(65535-1024) + 1024) // Generate a random port between 1024 and 65535
}