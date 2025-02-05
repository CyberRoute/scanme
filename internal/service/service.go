// Package service is helper package for services which is external data and need to be parsed
// to provide usefull information such as (port number, protocol and service name)
package service

import (
	"encoding/csv"
	"fmt"
	"os"
)

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
	file, err := os.Open("api/services.csv")
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
