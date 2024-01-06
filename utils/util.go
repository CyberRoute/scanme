package utils

import (
	"net"
)

func GetFreeTCPPort() (int, error) {
	// Listen on port 0 to get a free port assigned by the system.
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	// Get the actual address, including the assigned port.
	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}