// Package tcp provided way to get actual address including the assigned port
package tcp

import "net"

// Listen on port 0 to get a free port assigned by the system.
// Get the actual address, including the assigned port.
func GetFreeTCPPort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}
