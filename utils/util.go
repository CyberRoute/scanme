package utils

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
)

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

// ServiceInfo represents information about a service
type ServiceInfo struct {
	ServiceName string
	PortNumber  string
	Protocol    string
}

// GetServiceName opens the services.csv downloaded from
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
// and returns the service name for a given port number and protocol
func GetServiceName(port, proto string) (string, error) {
	file, err := os.Open("data/services.csv")
	if err != nil {
		return "", err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil {
		return "", err
	}

	for _, record := range records {
		if len(record) >= 3 && record[1] == port && record[2] == proto {
			return "(" + record[0] + ")", nil
		}
	}

	return "", fmt.Errorf("service not found for port %s and protocol %s", port, proto)
}
